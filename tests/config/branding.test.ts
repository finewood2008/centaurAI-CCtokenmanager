import { describe, expect, it } from "vitest";
import { PRODUCT_NAME } from "@/config/branding";

describe("TOKEN MANAGER branding", () => {
  it("uses the TOKEN MANAGER product name", () => {
    expect(PRODUCT_NAME).toBe("TOKEN MANAGER");
  });
});
