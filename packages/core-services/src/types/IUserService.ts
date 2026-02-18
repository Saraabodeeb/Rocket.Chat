export interface IUserService {
	ensureLoginTokensLimit(uid: string): Promise<void>;
	disable2FA(userId: string, code: string): Promise<boolean>;
}
