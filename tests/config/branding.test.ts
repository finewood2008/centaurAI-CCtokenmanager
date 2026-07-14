import { describe, expect, it } from "vitest";
import { PRODUCT_NAME } from "@/config/branding";

describe("CentaurAI Token Manager branding", () => {
  it("uses the CentaurAI product name", () => {
    expect(PRODUCT_NAME).toBe("CentaurAI Token Manager");
  });
});
