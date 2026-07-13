export const PRODUCT_NAME = "CentaurAI Token Manager";
export const SHOW_PROVIDER_PRESETS = false;

const COMMERCIAL_QUERY_KEYS = new Set([
  "aff",
  "affiliate",
  "ch",
  "code",
  "from",
  "ic",
  "invitecode",
  "ref",
  "referral",
  "source",
]);

function stripCommercialTracking(value?: string): string | undefined {
  if (!value) return value;

  try {
    const url = new URL(value);
    let changed = false;

    for (const key of [...url.searchParams.keys()]) {
      const normalizedKey = key.toLowerCase();
      if (
        COMMERCIAL_QUERY_KEYS.has(normalizedKey) ||
        normalizedKey.startsWith("utm_")
      ) {
        url.searchParams.delete(key);
        changed = true;
      }
    }

    return changed ? url.toString() : value;
  } catch {
    return value;
  }
}

/** Keep provider compatibility while removing upstream commercial placements. */
export function removeCommercialPromotion<
  T extends {
    isPartner?: boolean;
    partnerPromotionKey?: string;
    websiteUrl?: string;
    apiKeyUrl?: string;
  },
>(preset: T): void {
  preset.websiteUrl = stripCommercialTracking(preset.websiteUrl);
  preset.apiKeyUrl = stripCommercialTracking(preset.apiKeyUrl);

  if (!preset.isPartner) return;

  preset.isPartner = false;
  preset.partnerPromotionKey = undefined;
  preset.websiteUrl = "";
  preset.apiKeyUrl = undefined;
}
