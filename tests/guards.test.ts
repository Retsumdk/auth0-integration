import { createAuthMiddleware, requireRole, requirePermission, Auth0Client, AuthRequest } from '../src/index';

function mockRes() {
  const res: any = { statusCode: 0, body: null };
  res.status = (code: number) => { res.statusCode = code; return res; };
  res.json = (data: any) => { res.body = data; return res; };
  return res;
}

describe('requireRole', () => {
  const req = { auth: { sub: 'user-1', roles: ['admin'], token: 't' } } as AuthRequest;

  test('passes when the user has the required role', () => {
    const res = mockRes();
    let called = false;
    requireRole('admin')(req, res, () => { called = true; });
    expect(called).toBe(true);
    expect(res.statusCode).toBe(0);
  });

  test('passes with any of several required roles', () => {
    const res = mockRes();
    let called = false;
    requireRole(['editor', 'admin'])(req, res, () => { called = true; });
    expect(called).toBe(true);
  });

  test('403s when the role is missing', () => {
    const res = mockRes();
    requireRole('superadmin')(req as any, res, () => { throw new Error('should not call next'); });
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('Insufficient permissions');
  });

  test('401s when unauthenticated', () => {
    const res = mockRes();
    requireRole('admin')({} as AuthRequest, res, () => { throw new Error('should not call next'); });
    expect(res.statusCode).toBe(401);
  });
});

describe('requirePermission', () => {
  const req = { auth: { sub: 'user-1', permissions: ['read:users'], token: 't' } } as AuthRequest;

  test('passes when the user has the required permission', () => {
    const res = mockRes();
    let called = false;
    requirePermission('read:users')(req, res, () => { called = true; });
    expect(called).toBe(true);
  });

  test('403s when the permission is missing', () => {
    const res = mockRes();
    requirePermission('write:users')(req as any, res, () => { throw new Error('should not call next'); });
    expect(res.statusCode).toBe(403);
  });
});

describe('createAuthMiddleware', () => {
  test('401s when no bearer token is present', async () => {
    const client = new Auth0Client({ domain: 'example.auth0.com', audience: 'api', clientId: 'id', clientSecret: 'secret' });
    const middleware = createAuthMiddleware(client);
    const res = mockRes();
    let called = false;
    await middleware({ headers: {} } as any, res, () => { called = true; });
    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('No token provided');
    expect(called).toBe(false);
  });
});
