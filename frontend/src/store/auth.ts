import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";

import { client } from "./client";
import { LoginRequest, LoginResponse, LogoutRequest, RefreshRequest, RefreshResponse, RegisterRequest, RegisterResponse } from "../../generated/gateway_pb";

export const login = createAsyncThunk("login", async (args: { username: string, password: string }) => {
    const req = new LoginRequest();
    req.setUsername(args.username);
    req.setPassword(args.password);

    let res = await new Promise<LoginResponse>((resolve, reject) => {
        client.login(req, (err, response) => {
            if (response) {
                resolve(response);
            } else {
                reject(err ? err.message : "no response");
            }
        })
    });

    let user_id = res.getUserId_asB64();
    let session_token = res.getSessionToken_asB64();
    let refresh_token = res.getRefreshToken_asB64();

    return { user_id, session_token, refresh_token };
});

export const refresh = createAsyncThunk("refresh", async (args: Credentials) => {
    const req = new RefreshRequest();
    req.setUserId(args.user_id);
    req.setRefreshToken(args.refresh_token);

    let res = await new Promise<RefreshResponse>((resolve, reject) => {
        client.refresh(req, (err, response) => {
            if (response) {
                resolve(response);
            } else {
                reject(err ? err.message : "no response");
            }
        })
    });

    let session_token = res.getSessionToken_asB64();
    let refresh_token = res.getRefreshToken_asB64();

    return { user_id: args.user_id, session_token, refresh_token };
});

export const logout = createAsyncThunk("logout", async (args: Credentials) => {
    const req = new LogoutRequest();
    req.setUserId(args.user_id);
    req.setSessionToken(args.session_token);

    await new Promise((resolve, reject) => {
        client.logout(req, (err, response) => {
            if (response) {
                resolve(response);
            } else {
                reject(err ? err.message : "no response");
            }
        })
    });
});

export const register = createAsyncThunk("register", async (args: { username: string, password: string }) => {
    const req = new RegisterRequest();
    req.setUsername(args.username);
    req.setPassword(args.password);

    let res = await new Promise<RegisterResponse>((resolve, reject) => {
        client.register(req, (err, response) => {
            if (response) {
                resolve(response);
            } else {
                reject(err ? err.message : "no response");
            }
        })
    });

    let user_id = res.getUserId_asB64();
    let session_token = res.getSessionToken_asB64();
    let refresh_token = res.getRefreshToken_asB64();

    return { user_id, session_token, refresh_token };
});

export interface Credentials {
    user_id: string,
    session_token: string,
    refresh_token: string,
}

export interface Auth {
    loading: boolean,
    errors: string[],
    username_input: string,
    password_input: string,
    credentials?: Credentials
}

const initialState: Auth = {
    loading: false,
    errors: [],
    username_input: "",
    password_input: ""
};

export const authSlice = createSlice({
    name: "auth",
    initialState,
    reducers: {
        usernameChanged: (state, action: PayloadAction<string>) => {
            state.username_input = action.payload;
        },
        passwordChanged: (state, action: PayloadAction<string>) => {
            state.password_input = action.payload;
        },
        resetAttempt: (state) => {
            state.username_input = "";
            state.password_input = "";
            state.errors = [];
        }
    },
    extraReducers(builder) {
        builder.addCase(login.pending, (state) => {
            state.loading = true;
        }).addCase(login.fulfilled, (state, action) => {
            state.loading = false;
            state.credentials = action.payload;
            state.username_input = "";
            state.password_input = "";
            state.errors = [];
        }).addCase(login.rejected, (state) => {
            state.loading = false;
            state.errors = ["login failed"];
        }).addCase(register.pending, (state) => {
            state.loading = true;
        }).addCase(register.fulfilled, (state, action) => {
            state.loading = false;
            state.credentials = action.payload;
            state.username_input = "";
            state.password_input = "";
            state.errors = [];
        }).addCase(register.rejected, (state) => {
            state.loading = false;
            state.errors = ["registration failed"];
        }).addCase(logout.pending, (state) => {
            state.credentials = undefined;
        }).addCase(logout.rejected, () => {
            console.warn("logout request failed, session may still be active");
        })
    },
});

export const { usernameChanged, passwordChanged, resetAttempt } = authSlice.actions;
export default authSlice.reducer
