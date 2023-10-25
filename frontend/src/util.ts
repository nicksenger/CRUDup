export const refresh_interval = 86300000;

export async function sleep(ms: number) {
    await new Promise(resolve => setTimeout(resolve, ms));
}
