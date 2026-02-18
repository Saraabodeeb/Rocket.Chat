import { ServiceClassInternal } from '@rocket.chat/core-services';
import type { IUserService } from '@rocket.chat/core-services';
import { Users } from '@rocket.chat/models';

import { getMaxLoginTokens } from '../../lib/getMaxLoginTokens';
import { TOTP } from '../../../app/2fa/server/lib/totp';
import { notifyOnUserChange } from '../../../app/lib/server/lib/notifyListener';

// TODO merge this service with Account service
export class UserService extends ServiceClassInternal implements IUserService {
    protected name = 'user';

    async ensureLoginTokensLimit(uid: string): Promise<void> {
        const [{ tokens } = { tokens: [] }] = await Users.findAllResumeTokensByUserId(uid);
        if (tokens.length < getMaxLoginTokens()) {
            return;
        }

        const oldestDate = tokens.reverse()[getMaxLoginTokens() - 1];
        await Users.removeOlderResumeTokensByUserId(uid, oldestDate.when);
    }

    async disable2FA(userId: string, code: string): Promise<boolean> {
        const user = await Users.findOneById(userId);
        if (!user || !user.services?.totp?.enabled) {
            return false;
        }

        const verified = await TOTP.verify({
            secret: user.services.totp.secret,
            token: code,
            userId,
            backupTokens: user.services.totp.hashedBackup,
        });

        if (!verified) {
            return false;
        }

        const { modifiedCount } = await Users.disable2FAByUserId(userId);

        if (modifiedCount) {
            void notifyOnUserChange({ clientAction: 'updated', id: user._id, diff: { 'services.totp.enabled': false } });
            return true;
        }

        return false;
    }
}