exports.onExecutePostLogin = async (event, api) => {
    // Apply this rule only for Hereditas, and bypass it for other apps
    if (!event.client.metadata?.hereditas) {
        return;
    }

    // List of owners
    const owners = /*%OWNERS%*/;

    // Get metadata
    const requestTime = event.client.metadata.requestTime ? parseInt(event.client.metadata.requestTime, 10) : 0;
    const waitTime = parseInt(event.client.metadata.waitTime, 10);

    // Check if the user is an owner
    const isOwner = owners.some((email) => email === event.user.email);
    if (isOwner) {
        // Enrich the JWT with the app token
        api.idToken.setCustomClaim('https://hereditas.app', {
            role: 'owner',
            token: event.secrets.APP_TOKEN,
            requestTime: 0,
            waitTime: waitTime
        });
 
        // Reset the timer if it's running
        if (requestTime > 0) {
            api.user.setAppMetadata("requestTime", "0")
        }
        // Continue
        return;
    }
    else {
        const now = Date.now() / 1000;

        // For non-owners: first, check if the timer has been started already, and we've reached the wait time
        if (requestTime > 0) {
            // Enrich the JWT with the app token
            // If the wait time has passed, add the token
            const token = ((requestTime + waitTime) < now) ?
                event.secrets.APP_TOKEN :
                null;
            // Enrich the JWT
            api.idToken.setCustomClaim('https://hereditas.app', {
                role: 'user',
                token: token,
                requestTime: requestTime,
                waitTime: waitTime
            });

            // Continue
            return;
        }
        else {
            // Start the timer
            const data = {client_metadata: {requestTime: now.toString()}};
            api.user.setAppMetadata("requestTime", now.toString())
            api.idToken.setCustomClaim('https://hereditas.app', {
                role: 'user',
                requestTime: now,
                waitTime: waitTime
            });
        }
    }
};

