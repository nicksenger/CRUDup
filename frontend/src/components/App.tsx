import { useState } from "react";

import Input from "./Input";
import { useDispatch, useSelector } from "react-redux";
import { AppDispatch, RootState } from "../store";
import { login, register, logout, usernameChanged, passwordChanged, resetAttempt } from "../store/auth";

function App() {
	let dispatch = useDispatch<AppDispatch>();

	const [isRegister, setIsRegister] = useState(false);
	const isLoading = useSelector((state: RootState) => state.auth.loading);
	const { credentials, username_input, password_input, errors } = useSelector((state: RootState) => state.auth);
	let [username, password] = [username_input, password_input];

	const isValid = (username != "" && password != "");

	if (isLoading) {
		return (
			<main className="grid h-screen w-screen place-content-center">
				<span>Loading…</span>
			</main>
		)
	}

	if (credentials) {
		return (
			<main className="grid h-screen w-screen place-content-center">
				<span>You're in! <button className="text-blue-600" onClick={() => dispatch(logout(credentials))}>Logout</button></span>
			</main>
		)
	}

	return (
		<main className="grid h-screen w-screen place-content-center">
			<section className="flex flex-col items-center space-y-4">
				<h3 className="inline-block w-min font-bold">{isRegister ? "Register" : "Login"}</h3>
				<Input label="Username" value={username} onChange={(s) => dispatch(usernameChanged(s))} />
				<Input label="Password" value={password} onChange={(s) => dispatch(passwordChanged(s))} password={true} />
				{Boolean(errors.length) ? <>{errors.map(s => (<span className="text-red-600">{s}</span>))}</> : <></>}
				<button
					className={isValid ? `bg-blue-600 p-2 rounded-md text-white` : `bg-slate-600 p-2 rounded-md text-white`}
					disabled={!isValid}
					onClick={() => {
						if (isRegister) {
							dispatch(register({ username, password }))
						} else {
							dispatch(login({ username, password }))
						}
					}}>Go</button>
				<span className="">{isRegister ? "Already" : "Don't"} have an account? <button className="text-blue-600" onClick={() => {
					dispatch(resetAttempt());
					setIsRegister(!isRegister)
				}}>{isRegister ? "Login" : "Register"}</button>{isRegister ? "." : " to join."}</span>
			</section>
		</main>
	);
}

export default App;
