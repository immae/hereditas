const fetch = require('node-fetch');
exports.onExecutePostLogin = async (event, api) => {
    // Apply this rule only for Hereditas, and bypass it for other apps
    if (!event.client.metadata?.hereditas) {
        return;
    }

    const { WEBHOOK_URL } = event.secrets;

    // Skip if there's no webhook
    if (!WEBHOOK_URL || WEBHOOK_URL === '0') {
        return;
    }

    // List of owners
    const owners = /*%OWNERS%*/;

    // Trigger the webhook
    const role = (owners.some((email) => email === event.user.email)) ? 'owner' : 'user';
    const body = {
        value1: `New Hereditas login on ${(new Date()).toUTCString()}. User: ${event.user.email} (role: ${role})`,
        value2: event.user.email,
        value3: role
    };
    fetch(WEBHOOK_URL, {
        method: 'POST',
        body: JSON.stringify(body),
        headers: {'Content-Type': 'application/json'}
    })
        // Ensure the response has a valid status code
        .then((response) => {
            if (response.ok) {
                return;
            } else {
                return api.access.deny("Invalid response status code");
            }
        })
        // Catch errors and fail (fail the login even if the notification fails to send)
        .catch((err) => {
            console.error(err);
            return api.access.deny("Error sending the notification");
        });
};
