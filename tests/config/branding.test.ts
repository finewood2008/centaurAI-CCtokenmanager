import { describe, expect, it } from "vitest";
import {
  removeCommercialPromotion,
  SHOW_PROVIDER_PRESETS,
} from "@/config/branding";

describe("CentaurAI Token Manager branding", () => {
  it("keeps the preset provider directory disabled", () => {
    expect(SHOW_PROVIDER_PRESETS).toBe(false);
  });

  it("removes commercial metadata and links without dropping provider configs", () => {
    const preset = {
      name: "Partner provider",
      isPartner: true,
      partnerPromotionKey: "discount" as string | undefined,
      websiteUrl: "https://example.com/referral",
      apiKeyUrl: "https://example.com/signup?aff=upstream" as
        | string
        | undefined,
      endpoint: "https://api.example.com/v1",
    };

    removeCommercialPromotion(preset);

    expect(preset).toMatchObject({
      name: "Partner provider",
      endpoint: "https://api.example.com/v1",
      isPartner: false,
      websiteUrl: "",
    });
    expect(preset.partnerPromotionKey).toBeUndefined();
    expect(preset.apiKeyUrl).toBeUndefined();
  });

  it("strips referral tracking from ordinary provider links", () => {
    const preset = {
      websiteUrl: "https://example.com/docs?aff=upstream&lang=zh",
      apiKeyUrl: "https://example.com/keys?utm_source=ccswitch&tab=api",
    };

    removeCommercialPromotion(preset);

    expect(preset.websiteUrl).toBe("https://example.com/docs?lang=zh");
    expect(preset.apiKeyUrl).toBe("https://example.com/keys?tab=api");
  });
});
