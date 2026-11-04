import { AwsClient } from "aws4fetch";

const HOMEPAGE = "https://github.com/milkey-mouse/git-lfs-s3-proxy";
const EXPIRY = 3600;

const MIME = "application/vnd.git-lfs+json";

const METHOD_FOR = {
  upload: "PUT",
  download: "GET",
};

async function sign(s3, bucket, path, method) {
  const info = { method };
  const signed = await s3.sign(
    new Request(`https://${bucket}/${path}?X-Amz-Expires=${EXPIRY}`, info),
    { aws: { signQuery: true } },
  );
  return signed.url;
}

function unauthorized(message) {
  return new Response(JSON.stringify({ message }), {
    status: 401,
    headers: {
      "Content-Type": MIME,
      "LFS-Authenticate": 'Basic realm="git-lfs"',
      "WWW-Authenticate": 'Basic realm="git-lfs"',
    },
  });
}

function parseAuthorization(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    throw unauthorized("Credentials needed: an S3 access key ID and secret");
  }

  const [scheme, encoded] = auth.split(" ");
  if (scheme !== "Basic" || !encoded) {
    throw unauthorized("Use Basic auth: an S3 access key ID and secret");
  }

  let decoded;
  try {
    const buffer = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
    decoded = new TextDecoder().decode(buffer);
  } catch {
    throw unauthorized("Malformed Basic auth");
  }

  const index = decoded.indexOf(":");
  if (index === -1) {
    throw unauthorized("Malformed Basic auth");
  }

  return { user: decoded.slice(0, index), pass: decoded.slice(index + 1) };
}

// Signing needs no network, so a bad key would only fail later, on the signed URLs, where git-lfs retries a 401
// forever. One HEAD on the bucket refuses it here instead. Only a clear refusal counts: anything else carries on, and
// a real outage shows up on the transfers. Nothing from the store's response is passed on.
async function keyRefused(s3, bucket) {
  const signed = await s3.sign(new Request(`https://${bucket}`, { method: "HEAD" }));
  const { status } = await globalThis.fetch(signed);
  return status === 400 || status === 401 || status === 403;
}

async function handle(req, env) {
  const url = new URL(req.url);

  if (url.pathname == "/") {
    if (req.method === "GET") {
      return Response.redirect(HOMEPAGE, 302);
    } else {
      return new Response(null, { status: 405, headers: { Allow: "GET" } });
    }
  }

  if (!url.pathname.endsWith("/objects/batch")) {
    return new Response(null, { status: 404 });
  }

  if (req.method !== "POST") {
    return new Response(null, { status: 405, headers: { Allow: "POST" } });
  }

  // in practice, we'd rather not break out-of-spec clients not setting these
  /*if (!req.headers.get("Accept").startsWith(MIME)
    || !req.headers.get("Content-Type").startsWith(MIME)) {
    return new Response(null, { status: 406 });
  }*/

  const { user, pass } = parseAuthorization(req);
  let s3Options = { accessKeyId: user, secretAccessKey: pass };

  const segments = url.pathname.split("/").slice(1, -2);
  let params = {};
  let bucketIdx = 0;
  for (const segment of segments) {
    const sliceIdx = segment.indexOf("=");
    if (sliceIdx === -1) {
      break;
    } else {
      const key = decodeURIComponent(segment.slice(0, sliceIdx));
      const val = decodeURIComponent(segment.slice(sliceIdx + 1));
      s3Options[key] = val;

      bucketIdx++;
    }
  }

  const s3 = new AwsClient(s3Options);
  const bucket = segments.slice(bucketIdx).join("/");
  const expires_in = params.expiry || env.EXPIRY || EXPIRY;

  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ message: "Malformed JSON" }), {
      status: 400,
      headers: { "Content-Type": MIME },
    });
  }
  const { objects, operation, hash_algo = "sha256" } = body;

  if (hash_algo !== "sha256") {
    return new Response(
      JSON.stringify({
        message: `Hash algorithm '${hash_algo}' is not supported. Only 'sha256' is currently supported.`,
      }),
      {
        status: 409,
        headers: { "Content-Type": "application/vnd.git-lfs+json" },
      },
    );
  }

  if (await keyRefused(s3, bucket)) {
    return unauthorized("The object store refused this access key");
  }

  const method = METHOD_FOR[operation];
  const response = JSON.stringify({
    transfer: "basic",
    hash_algo: "sha256",
    objects: await Promise.all(
      objects.map(async ({ oid, size }) => ({
        oid,
        size,
        authenticated: true,
        actions: {
          [operation]: {
            href: await sign(s3, bucket, oid, method),
            expires_in,
          },
        },
      })),
    ),
  });

  return new Response(response, {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/vnd.git-lfs+json",
    },
  });
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch (e) {
      if (e instanceof Response) {
        return e;
      }
      throw e;
    }
  },
};
