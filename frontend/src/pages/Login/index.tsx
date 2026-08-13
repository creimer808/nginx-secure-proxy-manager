import { Field, Form, Formik } from "formik";
import { useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { Button, LocalePicker, Page, ThemeSwitcher } from "src/components";
import { useAuthState } from "src/context";
import { useHealth } from "src/hooks";
import { intl, T } from "src/locale";
import { validateEmail, validateString } from "src/modules/Validations";
import styles from "./index.module.css";

function TwoFactorForm() {
	const codeRef = useRef<HTMLInputElement>(null);
	const [formErr, setFormErr] = useState("");
	const { verifyTwoFactor, cancelTwoFactor } = useAuthState();

	const onSubmit = async (values: any, { setSubmitting }: any) => {
		setFormErr("");
		try {
			await verifyTwoFactor(values.code);
		} catch (err) {
			if (err instanceof Error) {
				setFormErr(err.message);
			}
		}
		setSubmitting(false);
	};

	useEffect(() => {
		codeRef.current?.focus();
	}, []);

	return (
		<>
			<h2 className="h2 text-center mb-4">
				<T id="login.2fa-title" />
			</h2>
			<p className="text-secondary text-center mb-4">
				<T id="login.2fa-description" />
			</p>
			{formErr !== "" && <Alert variant="danger">{formErr}</Alert>}
			<Formik initialValues={{ code: "" }} onSubmit={onSubmit}>
				{({ isSubmitting }) => (
					<Form>
						<div className="mb-3">
							<Field name="code" validate={validateString(6, 20)}>
								{({ field, form }: any) => (
									<label className="form-label">
										<T id="login.2fa-code" />
										<input
											{...field}
											ref={codeRef}
											type="text"
											inputMode="numeric"
											autoComplete="one-time-code"
											required
											maxLength={20}
											className={`form-control ${form.errors.code && form.touched.code ? "is-invalid" : ""}`}
											placeholder={intl.formatMessage({ id: "login.2fa-code-placeholder" })}
										/>
										<div className="invalid-feedback">{form.errors.code}</div>
									</label>
								)}
							</Field>
						</div>
						<div className="form-footer d-flex gap-2">
							<Button type="button" fullWidth onClick={cancelTwoFactor} disabled={isSubmitting}>
								<T id="cancel" />
							</Button>
							<Button type="submit" fullWidth color="azure" isLoading={isSubmitting}>
								<T id="login.2fa-verify" />
							</Button>
						</div>
					</Form>
				)}
			</Formik>
		</>
	);
}

function LoginForm() {
	const emailRef = useRef<HTMLInputElement>(null);
	const [formErr, setFormErr] = useState("");
	const { login } = useAuthState();

	const onSubmit = async (values: any, { setSubmitting }: any) => {
		setFormErr("");
		try {
			await login(values.email, values.password);
		} catch (err) {
			if (err instanceof Error) {
				setFormErr(err.message);
			}
		}
		setSubmitting(false);
	};

	useEffect(() => {
		emailRef.current?.focus();
	}, []);

	return (
		<>
			<h2 className="h2 text-center mb-4">
				<T id="login.title" />
			</h2>
			{formErr !== "" && <Alert variant="danger">{formErr}</Alert>}
			<Formik
				initialValues={
					{
						email: "",
						password: "",
					} as any
				}
				onSubmit={onSubmit}
			>
				{({ isSubmitting }) => (
					<Form>
						<div className="mb-3">
							<Field name="email" validate={validateEmail()}>
								{({ field, form }: any) => (
									<label className="form-label">
										<T id="email-address" />
										<input
											{...field}
											ref={emailRef}
											type="email"
											required
											className={`form-control ${form.errors.email && form.touched.email ? " is-invalid" : ""}`}
											placeholder={intl.formatMessage({ id: "email-address" })}
										/>
										<div className="invalid-feedback">{form.errors.email}</div>
									</label>
								)}
							</Field>
						</div>
						<div className="mb-2">
							<Field name="password" validate={validateString(8, 255)}>
								{({ field, form }: any) => (
									<>
										<label className="form-label">
											<T id="password" />
											<input
												{...field}
												type="password"
												autoComplete="current-password"
												required
												maxLength={255}
												className={`form-control ${form.errors.password && form.touched.password ? " is-invalid" : ""}`}
												placeholder={intl.formatMessage({ id: "password" })}
											/>
											<div className="invalid-feedback">{form.errors.password}</div>
										</label>
									</>
								)}
							</Field>
						</div>
						<div className="form-footer">
							<Button type="submit" fullWidth color="azure" isLoading={isSubmitting}>
								<T id="sign-in" />
							</Button>
						</div>
					</Form>
				)}
			</Formik>
		</>
	);
}

export default function Login() {
	const { twoFactorChallenge } = useAuthState();
	const health = useHealth();

	return (
		<Page className="page page-center">
			<div className="container container-tight py-4">
				<div className="d-flex justify-content-between align-items-center mb-4 ps-4 pe-3">
					<div className={styles.brand}>
						<img src="/images/nspm-shield.svg" alt="" width={48} height={54} />
						<span>Nginx Secure Proxy Manager</span>
					</div>
					<div className="d-flex align-items-center gap-1">
						<LocalePicker />
						<ThemeSwitcher />
					</div>
				</div>
				<div className="card card-md">
					<div className="card-body">{twoFactorChallenge ? <TwoFactorForm /> : <LoginForm />}</div>
				</div>
				{health.data && (
					<div className="text-center text-secondary mt-3">
						<a
							href={`https://github.com/creimer808/nginx-proxy-manager/releases/tag/v${health.data.appVersion}`}
							className="link-secondary"
							target="_blank"
							rel="noopener noreferrer"
						>
							<T id="version.app" data={{ version: health.data.appVersion }} />
						</a>
						<span aria-hidden="true"> · </span>
						<a
							href={`https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v${health.data.upstreamVersion}`}
							className="link-secondary"
							target="_blank"
							rel="noopener noreferrer"
						>
							<T id="version.upstream" data={{ version: health.data.upstreamVersion }} />
						</a>
					</div>
				)}
			</div>
		</Page>
	);
}
