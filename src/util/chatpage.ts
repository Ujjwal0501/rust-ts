export async function fetchWithDelay(url: string, options?: RequestInit): Promise<void> {
    while (true) {
        await new Promise(resolve => setTimeout(resolve, 1000)); // Delay for 1 second
        try {
            const response = await fetch(url, { ...options, method: 'POST' });
            console.log('Fetch successful:', response.status);
        } catch (error) {
            console.error('Fetch failed:', error);
        }
    }
}
