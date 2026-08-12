/// <reference types="cypress" />

describe('Dashboard endpoints', () => {
	let token;

	before(() => {
		cy.resetUsers();
		cy.getToken().then((tok) => {
			token = tok;
		});
	});

	it('Should be able to get host counts', () => {
		cy.task('backendApiGet', {
			token: token,
			path:  '/api/reports/hosts'
		}).then((data) => {
			cy.validateSwaggerSchema('get', 200, '/reports/hosts', data);
			expect(data).to.have.property('dead');
			expect(data).to.have.property('proxy');
			expect(data).to.have.property('redirection');
			expect(data).to.have.property('stream');
		});
	});

});

describe('Security & Traffic dashboard report', () => {
	let token;

	before(() => {
		cy.resetUsers();
		cy.getToken().then((tok) => {
			token = tok;
		});
	});

	const VALID_RANGES = ['24h', '7d', '30d'];

	VALID_RANGES.forEach((range) => {
		it(`Should return a valid report for range ${range}`, () => {
			cy.task('backendApiGet', {
				token: token,
				path:  `/api/reports/dashboard?range=${range}`
			}).then((data) => {
				cy.validateSwaggerSchema('get', 200, '/reports/dashboard', data);
				expect(data.range).to.equal(range);
				expect(data).to.have.property('generated_at');
				expect(data.collection).to.have.property('enabled');
				expect(data).to.have.property('posture');
				expect(data).to.have.property('traffic');
				expect(data.traffic).to.have.property('requests');
				expect(data.series).to.be.an('array');
				expect(data.top_hosts).to.be.an('array');
				expect(data.top_sources).to.have.property('approximate', true);
				expect(data.top_sources.items).to.be.an('array');
			});
		});
	});

	it('Should reject an invalid range with 400', () => {
		cy.task('backendApiGet', {
			token:         token,
			path:          '/api/reports/dashboard?range=99d',
			returnOnError: true
		}).then((data) => {
			expect(data).to.have.property('error');
			expect(data.error.code).to.equal(400);
		});
	});

	it('Should reject a missing range with 400', () => {
		cy.task('backendApiGet', {
			token:         token,
			path:          '/api/reports/dashboard',
			returnOnError: true
		}).then((data) => {
			expect(data).to.have.property('error');
			expect(data.error.code).to.equal(400);
		});
	});

	it('Should return zeroed traffic and empty series for an unseeded database', () => {
		cy.task('backendApiGet', {
			token: token,
			path:  '/api/reports/dashboard?range=24h'
		}).then((data) => {
			expect(data.traffic.requests).to.equal(0);
			expect(data.traffic.bytes_sent).to.equal(0);
			expect(data.series).to.deep.equal([]);
			expect(data.top_hosts).to.deep.equal([]);
			expect(data.top_sources.items).to.deep.equal([]);
		});
	});

	it('Should send Cache-Control: private, no-store because raw IPs may be present', () => {
		cy.request({
			url:               '/api/reports/dashboard?range=24h',
			headers:           { Authorization: `Bearer ${token}` },
			failOnStatusCode:  false
		}).then((response) => {
			expect(response.status).to.equal(200);
			const cacheControl = response.headers['cache-control'];
			expect(cacheControl).to.match(/private/);
			expect(cacheControl).to.match(/no-store/);
		});
	});

	it('Should not expose another user\'s hosts to a user without global visibility', () => {
		// Admin owns a proxy host; a second user with visibility=user must not see it.
		cy.task('backendApiPost', {
			token: token,
			path:  '/api/nginx/proxy-hosts',
			data:  {
				domain_names:            ['visibility-test.example.com'],
				forward_scheme:          'http',
				forward_host:            '1.1.1.1',
				forward_port:            80,
				access_list_id:          '0',
				certificate_id:          0,
				meta:                    { dns_challenge: false },
				advanced_config:         '',
				locations:               [],
				block_exploits:          false,
				caching_enabled:         false,
				allow_websocket_upgrade: false,
				http2_support:           false,
				hsts_enabled:            false,
				hsts_subdomains:         false,
				ssl_forced:              false
			}
		}).then(() => {
			// Admin can see the host in posture.
			cy.task('backendApiGet', {
				token: token,
				path:  '/api/reports/dashboard?range=24h'
			}).then((adminData) => {
				expect(adminData.posture.enabled).to.be.greaterThan(0);
			});
		});

		// Create a second user with visibility limited to their own items.
		cy.task('backendApiPost', {
			token: token,
			path:  '/api/users',
			data: {
				name:     'Limited User',
				nickname: 'Limited',
				email:    'limited@example.com',
				auth:     { type: 'password', secret: 'changeme' }
			}
		}).then((user) => {
			expect(user.id).to.be.greaterThan(0);
			cy.task('backendApiPut', {
				token: token,
				path:  `/api/users/${user.id}/permissions`,
				data:  {
					visibility:         'user',
					proxy_hosts:        'view',
					redirection_hosts:  'hidden',
					dead_hosts:         'hidden',
					streams:            'hidden',
					access_lists:       'hidden',
					certificates:       'hidden'
				}
			}).then(() => {
				// Token for the limited user.
				cy.task('backendApiPost', {
					path: '/api/tokens',
					data: { identity: 'limited@example.com', secret: 'changeme' }
				}).then((res) => {
					const limitedToken = res.token;
					cy.task('backendApiGet', {
						token: limitedToken,
						path:  '/api/reports/dashboard?range=24h'
					}).then((limitedData) => {
						cy.validateSwaggerSchema('get', 200, '/reports/dashboard', limitedData);
						// The limited user must not observe the admin's host in posture or top hosts.
						expect(limitedData.posture.enabled).to.equal(0);
						expect(limitedData.top_hosts).to.deep.equal([]);
					});

					// Hiding proxy hosts must also deny direct API access, not only hide the UI.
					cy.task('backendApiPut', {
						token: token,
						path:  `/api/users/${user.id}/permissions`,
						data:  {
							visibility:         'all',
							proxy_hosts:        'hidden',
							redirection_hosts:  'hidden',
							dead_hosts:         'hidden',
							streams:            'hidden',
							access_lists:       'hidden',
							certificates:       'hidden'
						}
					}).then(() => {
						cy.task('backendApiGet', {
							token:         limitedToken,
							path:          '/api/reports/dashboard?range=24h',
							returnOnError: true
						}).then((denied) => {
							expect(denied.error.code).to.equal(403);
						});
					});
				});
			});
		});
	});
});
