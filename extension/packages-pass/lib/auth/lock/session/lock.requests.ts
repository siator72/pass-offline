import { api } from '../../../api/api';
import { type Lock, LockMode } from '../types';

export const checkSessionLock = async (): Promise<Lock> => {
    try {
        /* Offline build: server-side lock check removed. The lock state is
         * resolved from the local auth store only. */
        const LockInfo = undefined;
        return {
            mode: LockInfo?.Exists ? LockMode.SESSION : LockMode.NONE,
            locked: false,
            ttl: LockInfo?.UnlockedSecs ?? undefined,
        };
    } catch (e: any) {
        if (e?.name === 'LockedSession') return { mode: LockMode.SESSION, locked: true };
        throw e;
    }
};

export const forceSessionLock = async (): Promise<void> => {
    await api({
        url: 'pass/v1/user/session/lock/force_lock',
        method: 'post',
    });
};

export const createSessionLock = async (LockCode: string, UnlockedSecs: number): Promise<string> =>
    (
        await api({
            url: 'pass/v1/user/session/lock',
            method: 'post',
            data: { LockCode, UnlockedSecs },
        })
    ).LockData!.StorageToken;

export const deleteSessionLock = async (LockCode: string): Promise<string> =>
    (
        await api({
            url: 'pass/v1/user/session/lock',
            method: 'delete',
            data: { LockCode },
        })
    ).LockData!.StorageToken;

export const unlockSession = async (LockCode: string): Promise<string> =>
    (
        await api({
            url: 'pass/v1/user/session/lock/unlock',
            method: 'post',
            data: { LockCode },
        })
    ).LockData!.StorageToken;
