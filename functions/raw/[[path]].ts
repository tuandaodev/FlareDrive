import { notFound, parseBucketPath } from "@/utils/bucket";

export async function onRequestGet(context) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const obj = await bucket.get(path);
  if (obj === null) return notFound();

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  if (path.startsWith("_$flaredrive$/thumbnails/"))
    headers.set("Cache-Control", "max-age=31536000");

  return new Response(obj.body, { headers });
}

async function verifyToken(request) {
  const url = new URL(request.url);
  const verifyParam = url.searchParams.get('verify');

  if (!verifyParam) {
    return false;
  }

  const [timestamp, token] = verifyParam.split('-');

  // Calculate the expected HMAC

  //return await calculateHMAC(timestamp, secretKey, url.pathname);

  if (!verifyTime(timestamp))
    return false;

  const expectedHMAC = await calculateHMAC(timestamp, HASH_SECRET_KEY, url.pathname);

  // Compare the expected HMAC with the provided token
  if (token === expectedHMAC) {
    return true;
  }

  return false;
}

function verifyTime(timestamp) {
	if(Math.round(new Date().getTime()/1000) - timestamp > 30) {
		return false;
	}
  return true;
}

async function calculateHMAC(timestamp, secretKey, path) {
  const textToSign = path + timestamp;
  const encoder = new TextEncoder();
  const data = encoder.encode(textToSign);
  const key = encoder.encode(secretKey);
  const hashBuffer = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signatureBuffer = await crypto.subtle.sign('HMAC', hashBuffer, data);
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  return btoa(String.fromCharCode(...signatureArray));
}