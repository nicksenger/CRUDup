/**
 * @type {import('@rspack/cli').Configuration}
 */
module.exports = {
	context: __dirname,
	entry: {
		main: "./src/main.tsx"
	},
	builtins: {
		html: [
			{
				template: "./index.html",
				favicon: './favicon.ico',
			}
		]
	},
	module: {
		rules: [
			{
				test: /\.svg$/,
				type: "asset"
			},
			{
				test: /\.css$/,
				use: [
					{
						loader: 'postcss-loader',
						options: {
							postcssOptions: {
								plugins: {
									tailwindcss: {},
									autoprefixer: {},
								},
							},
						},
					},
				],
				type: 'css',
			},
		]
	},
	devServer: {
		proxy: {
			'/gateway.Gateway': {
				target: 'http://0.0.0.0:50051',
				changeOrigin: true,
				pathRewrite: (s) => {
					return s;
				}
			},
		},
	},
};
