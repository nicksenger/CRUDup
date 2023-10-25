import { configureStore, createListenerMiddleware, isAnyOf, isFulfilled } from "@reduxjs/toolkit";

import authReducer, { Credentials, login, logout, refresh, register } from "./auth";
import { sleep, refresh_interval } from "../util";

const listenerMiddleware = createListenerMiddleware();
listenerMiddleware.startListening({
    matcher: isAnyOf(login.fulfilled, login.rejected, register.fulfilled, register.rejected, logout.fulfilled),
    effect: async (action, listenerApi) => {
        listenerApi.cancelActiveListeners();

        if (isFulfilled(action)) {
            await sleep(refresh_interval);
            listenerApi.dispatch(refresh(action.payload as Credentials));
        }
    }
});

export const store = configureStore({
    reducer: {
        auth: authReducer
    },
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch