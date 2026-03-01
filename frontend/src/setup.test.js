import { describe, it, expect } from 'vitest';

describe('Frontend Setup', () => {
  it('should pass this basic test', () => {
    expect(true).toBe(true);
  });
  
  it('should have correct environment', () => {
    expect(process.env.NODE_ENV).toBeDefined();
  });
});
