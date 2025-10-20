import { request } from '@nativescript/core/http';
import { SecureStorage } from '@nativescript/secure-storage';
import { PARSE_APP_ID, PARSE_REST_API_KEY, PARSE_SERVER_URL } from '../configs/parse.constants';
import { UserIdentity } from '../models/UserIdentity';
import { SignupResult } from '../models/enums/SignupResult';
import { LoginResult } from '../models/enums/LoginResult';

const SESSION_TOKEN_KEY = 'parse_session_token';
const USER_DATA_KEY = 'parse_user_data';

const secureStorage = new SecureStorage();

export class UserService {
  private static getHeaders(sessionToken: string | null = null) {
    const headers: any = {
      'X-Parse-Application-Id': PARSE_APP_ID,
      'X-Parse-REST-API-Key': PARSE_REST_API_KEY,
      'Content-Type': 'application/json',
    };
    if (sessionToken) {
      headers['X-Parse-Session-Token'] = sessionToken;
    }
    return headers;
  }

  static async signUpUser(username: string, email: string, password: string): Promise<SignupResult> {
    const lowercasedEmail = email.toLowerCase();
    try {
      const response = await request({
        url: `${PARSE_SERVER_URL}/users`,
        method: 'POST',
        headers: this.getHeaders(),
        content: JSON.stringify({ username, email: lowercasedEmail, password }),
      });

      if (response.statusCode === 201 && response.content) {
        const responseData = response.content.toJSON();
        const user: UserIdentity = { ...responseData, username, email: lowercasedEmail };

        await secureStorage.set({
          key: SESSION_TOKEN_KEY,
          value: user.sessionToken,
        });
        await secureStorage.set({
          key: USER_DATA_KEY,
          value: JSON.stringify(user),
        });
        
        console.log('User signed up successfully!');
        return SignupResult.CREATED;
      } else {
        if (response.content) {
          const errorData = response.content.toJSON();
          if (errorData.code === 202) {
            console.error('Signup failed: Username already exists.');
            return SignupResult.EXISTING_USERNAME;
          }
          if (errorData.code === 203) {
            console.error('Signup failed: Email already exists.');
            return SignupResult.EXISTING_EMAIL;
          }
        }
        const errorMessage = response.content ? response.content.toString() : `HTTP Error: ${response.statusCode}`;
        console.error('Error signing up user', errorMessage);
        return SignupResult.ERROR;
      }
    } catch (error) {
      console.error('Error signing up user:', error);
      return SignupResult.ERROR;
    }
  }

  static async logInUser(username: string, password: string): Promise<LoginResult> {
    try {
      // The parameters are encoded in the URL for a GET request
      const url = `${PARSE_SERVER_URL}/login?username=${encodeURIComponent(username)}&password=${encodeURIComponent(
        password
      )}`;

      const response = await request({
        url: url,
        method: 'GET',
        headers: this.getHeaders(),
      });

      if (response.statusCode >= 200 && response.statusCode < 300 && response.content) {
        const user: UserIdentity = response.content.toJSON();
        // Use secureStorage instead of ApplicationSettings
        await secureStorage.set({
          key: SESSION_TOKEN_KEY,
          value: user.sessionToken,
        });
        await secureStorage.set({
          key: USER_DATA_KEY,
          value: JSON.stringify(user),
        });
        console.log('User logged in:', user);
        return LoginResult.SUCCESS;
      } else {
        if (response.content) {
          const errorData = response.content.toJSON();
          if (errorData.code === 101) {
            if (errorData.error.includes('Your account is locked')) {
              console.error('Login failed: Account is locked.');
              return LoginResult.ACCOUNT_LOCKED;
            }
            console.error('Login failed: Invalid credentials.');
            return LoginResult.INVALID_CREDENTIALS;
          }
        }
        const errorMessage = response.content ? response.content.toString() : `HTTP Error: ${response.statusCode}`;
        console.error('Error logging in user:', errorMessage);
        return LoginResult.ERROR;
      }
    } catch (error) {
      console.error('Error logging in user:', error);
      return LoginResult.ERROR;
    }
  }

  static async resetPassword(email: string): Promise<boolean> {
    try {
      const response = await request({
        url: `${PARSE_SERVER_URL}/requestPasswordReset`,
        method: 'POST',
        headers: this.getHeaders(),
        content: JSON.stringify({ email }),
      });

      if (response.statusCode === 200) {
        console.log(`Password reset email sent to ${email}`);
        return true;
      } else {
        const errorMessage = response.content ? response.content.toString() : `HTTP Error: ${response.statusCode}`;
        console.error('Error requesting password reset:', errorMessage);
        return false;
      }
    } catch (error) {
      console.error('Error during password reset request:', error);
      return false;
    }
  }

  static async logOutUser(): Promise<void> {
    const sessionToken = await this.getSessionToken();
    if (!sessionToken) {
      console.log('No user was logged in.');
      return;
    }
    try {
      await request({
        url: `${PARSE_SERVER_URL}/logout`,
        method: 'POST',
        headers: this.getHeaders(sessionToken),
      });
      console.log('User logged out successfully.');
    } catch (error) {
      console.error('Error logging out user:', error);
    } finally {
      // Always clear local data when logging out
      await secureStorage.remove({ key: SESSION_TOKEN_KEY });
      await secureStorage.remove({ key: USER_DATA_KEY });
    }
  }

  static async getCurrentUser(): Promise<UserIdentity | null> {
    const userData = await secureStorage.get({ key: USER_DATA_KEY });
    if (userData) {
      return JSON.parse(userData);
    }
    return null;
  }

  static async getSessionToken(): Promise<string | null> {
    return await secureStorage.get({ key: SESSION_TOKEN_KEY });
  }
}
