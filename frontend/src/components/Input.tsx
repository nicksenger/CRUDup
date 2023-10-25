export type InputProps = {
    label: string,
    value: string,
    onChange: (s: string) => void,
    password?: boolean
};

function Input({ label, value, onChange, password }: InputProps) {
    return (
        <label>
            {label}:
            <input
                type={password ? "password" : "text"}
                onChange={e => onChange(e.target.value)}
                value={value}
                className="shadow-sm border-gray-300 rounded-lg m-2 focus:ring-2 focus:ring-indigo-200 focus:border-indigo-400"
            />
        </label>
    );
}

export default Input;
