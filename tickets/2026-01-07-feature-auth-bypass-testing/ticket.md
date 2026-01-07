# Feature Request: Global Auth Bypass for Testing

**GitHub Issue:** #4
**Date:** 2026-01-07
**Branch:** feature/auth-bypass-testing
**Status:** Planning

## Summary

For testing and local development, it's often needed to bypass authentication entirely to focus on business logic without setting up JWT/API key infrastructure.

## Use Case

- Local development without auth server
- Integration testing without token generation
- Quick prototyping and debugging
- CI/CD pipelines without auth infrastructure

## Requirements

1. Must be impossible to accidentally enable in production
2. Must be obvious when active (logging)
3. Must inject a real user object (not skip auth entirely)
4. Must be configurable for different test scenarios
5. Must maintain all downstream code paths (permissions, audit logs)

## Acceptance Criteria

- [ ] Two environment variables required for activation (defense in depth)
- [ ] WARNING logged on every bypassed request
- [ ] Configurable test user via environment variables
- [ ] New AuthMethod.BYPASS enum value
- [ ] Documentation for usage
- [ ] Tests covering bypass functionality
