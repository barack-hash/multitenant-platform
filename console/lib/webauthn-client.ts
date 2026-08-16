'use client';
// Browser-side WebAuthn. Converts the Hub's base64url options into the ArrayBuffers that
// navigator.credentials needs, and the authenticator's result back into base64url for the finish call.
const toBuf = (b64u: string) => {
  const s = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
};
const toB64u = (buf: ArrayBuffer) => {
  let bin = '';
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export async function registerPasskey(): Promise<{ registered?: boolean; error?: string }> {
  const begin = await (await fetch('/api/webauthn/register/begin', { method: 'POST' })).json();
  if (begin.error) return { error: begin.error };
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: toBuf(begin.challenge),
      rp: begin.rp,
      user: { id: new TextEncoder().encode(begin.user.id), name: begin.user.name, displayName: begin.user.displayName },
      pubKeyCredParams: begin.pubKeyCredParams,
      authenticatorSelection: begin.authenticatorSelection,
      timeout: begin.timeout,
      attestation: 'none',
    },
  })) as PublicKeyCredential;
  const att = cred.response as AuthenticatorAttestationResponse;
  return (await fetch('/api/webauthn/register/finish', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ challenge_id: begin.challenge_id, attestationObject: toB64u(att.attestationObject), clientDataJSON: toB64u(att.clientDataJSON) }),
  })).json();
}

export async function loginPasskey(email: string): Promise<{ ok?: boolean; acr?: string; error?: string }> {
  const begin = await (await fetch('/api/webauthn/login/begin', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }) })).json();
  if (begin.error) return { error: begin.error };
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: toBuf(begin.challenge),
      rpId: begin.rpId,
      allowCredentials: begin.allowCredentials.map((c: { id: string }) => ({ type: 'public-key' as const, id: toBuf(c.id) })),
      userVerification: begin.userVerification,
      timeout: 300000,
    },
  })) as PublicKeyCredential;
  const asr = assertion.response as AuthenticatorAssertionResponse;
  return (await fetch('/api/webauthn/login/finish', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge_id: begin.challenge_id, credentialId: toB64u(assertion.rawId),
      authenticatorData: toB64u(asr.authenticatorData), clientDataJSON: toB64u(asr.clientDataJSON), signature: toB64u(asr.signature),
    }),
  })).json();
}

export const supportsWebAuthn = () => typeof window !== 'undefined' && !!window.PublicKeyCredential;
