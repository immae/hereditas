exports.onExecutePostLogin = async (event, api) => {
    // Apply this rule only for Hereditas, and bypass it for other apps
    if (!event.client.metadata?.hereditas) {
        return;
    }

    // List of authorized users
    const whitelist = /*%ALL_USERS%*/;

    // Access should only be granted to verified users.
    if (!event.user.email || !event.user.email_verified) {
        return api.access.deny('Access denied.');
    }

    // Check if the user's email address is whitelisted
    const userHasAccess = whitelist.some((email) => email === event.user.email);
    if (!userHasAccess) {
        return api.access.deny('Access denied.');
    }
};
