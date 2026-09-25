// Base URL for your FastAPI backend
const API_BASE_URL = 'http://localhost:8000/api';

async function registerUser(userData) {
    try {
        const response = await fetch(`${API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(userData)
        });

        const data = await response.json();

        if (!response.ok) {
            // Throw the error message sent from FastAPI (e.g., "Email already registered")
            throw new Error(data.detail || 'Registration failed');
        }

        return data; // Returns the success message and user_id
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}