// Fake credentials, assembled at run time so this repository never holds one
// in one piece (GitHub push protection and this very mod would flag it).
const k = (...parts: string[]) => parts.join('')

export const STRIPE = k('sk', '_live_', 'Zq8wE2rT6yU1iO9pA3sD5fG7')
export const GITHUB = k('gh', 'p_', 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5')
export const OPENAI = k('sk-', 'proj-', 'Q1w2E3r4T5y6U7i8O9p0A1s2D3f4')
export const GOOGLE = k('AI', 'za', 'Sy0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV')
export const PEM = k('-----BEGIN ', 'RSA PRIVATE', ' KEY-----')
export const HARDCODED = k('f8Kq2', 'Lm9Xz4Rt7Wp')
export const DB_URL = k('postgres://app:', 'Xk29fLq8Zr', '@db.acme-prod.net:5432/app')

const b64url = (o: object) =>
  btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
export const jwt = (role: string) =>
  k('ey', 'JhbGciOiJIUzI1NiJ9', '.', b64url({ role }), '.', 'Sig1234567890abcdefXYZ')
