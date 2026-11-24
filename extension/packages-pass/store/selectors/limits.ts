import { createSelector } from '@reduxjs/toolkit';

import { selectAllAliasItems, selectAllLoginItems } from './items';
import { selectAllVaults } from './shares';

/* Offline/unlimited build: all plan-based limits are disabled.
 * Item storage is local, so there is no server-imposed cap. */

export const selectVaultLimits = createSelector([selectAllVaults], (vaults) => {
    return {
        vaultLimit: Number.MAX_SAFE_INTEGER,
        vaultTotalCount: vaults.length,
        vaultLimitReached: false,
        didDowngrade: false,
    };
});

export const selectAliasLimits = createSelector([selectAllAliasItems], (aliases) => {
    return {
        aliasLimit: Number.MAX_SAFE_INTEGER,
        aliasLimited: false,
        aliasTotalCount: aliases.length,
        needsUpgrade: false,
        didDowngrade: false,
    };
});

export const selectTOTPLimits = createSelector([selectAllLoginItems], (loginItems) => {
    return {
        totpLimit: undefined,
        needsUpgrade: false,
        didDowngrade: false,
        totpAllowed: () => true,
        totpTotalCount: loginItems.filter((item) => Boolean(item.data.content.totpUri.v.length)).length,
    };
});

export const selectExtraFieldLimits = createSelector([() => null], () => {
    return { needsUpgrade: false };
});
