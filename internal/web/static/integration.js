(() => {
  const form = document.getElementById('integration-connect-form');
  if (!form) return;
  const status = document.getElementById('integration-status');
  const workspace = document.getElementById('integration-workspace');
  const list = document.getElementById('application-list');
  const output = document.getElementById('secret-output');
  const csrf = () => (document.cookie.split('; ').find(v => v.startsWith('mutandae_csrf=')) || '').split('=')[1] || '';
  const json = async (url, options = {}) => {
    options.credentials = 'same-origin';
    options.headers = Object.assign({'Accept': 'application/vnd.mutandae.v1+json'}, options.headers || {});
    if (options.body) {
      options.headers['Content-Type'] = 'application/json';
      options.headers['X-Mutandae-CSRF'] = csrf();
    }
    const response = await fetch(url, options);
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error?.message || 'Request failed');
    return body;
  };
  const showError = error => {
    status.textContent = error.message;
    status.className = 'form-status error';
  };
  const receipt = value => value?.correlation_id ? ` · event ${value.event_published ? 'published' : 'not published'} · ${value.correlation_id}` : '';
  const showSecret = (secret, operation) => {
    output.classList.remove('is-hidden');
    output.replaceChildren();
    const title = document.createElement('strong');
    title.textContent = operation + (secret.one_time ? ' — copy it now' : '');
    output.append(title);
    const note = document.createElement('p');
    note.textContent = secret.vault ? `Vault reference: ${secret.vault.secret_name} (version ${secret.vault.version || 'current'})` : 'This value is not stored by Mutandae and cannot be recovered after this response.';
    output.append(note);
    if (secret.secret_text) {
      const code = document.createElement('code');
      code.textContent = secret.secret_text;
      output.append(code);
    }
  };
  const renderApps = apps => {
    list.replaceChildren();
    if (!apps.length) {
      const p = document.createElement('p');
      p.className = 'muted';
      p.textContent = 'No applications were returned.';
      list.append(p);
      return;
    }
    apps.forEach(app => {
      const card = document.createElement('article');
      card.className = 'application-card';
      const heading = document.createElement('h3');
      heading.textContent = app.display_name || app.application_id;
      card.append(heading);
      const meta = document.createElement('p');
      meta.className = 'muted';
      meta.textContent = `Object ${app.object_id} · Client ${app.application_id} · ${app.owned_by_calling_client ? 'owned by this client' : 'read-only'}`;
      card.append(meta);
      if (app.owned_by_calling_client) {
        const controls = document.createElement('div');
        controls.className = 'application-controls';
        const name = document.createElement('input');
        name.placeholder = 'credential display name';
        name.value = 'mutandae-demo-secret';
        name.maxLength = 120;
        const vault = document.createElement('label');
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = document.getElementById('vault-enabled').checked;
        vault.append(checkbox, ' store in configured vault');
        const create = document.createElement('button');
        create.className = 'button button-small';
        create.textContent = 'Create secret';
        create.onclick = async () => {
          try {
            const body = await json('/api/v1/integration/secrets', {method: 'POST', body: JSON.stringify({application_object_id: app.object_id, display_name: name.value, store_in_vault: checkbox.checked})});
            showSecret(body.secret, 'Secret created' + receipt(body.receipt));
            await loadApps();
          } catch (error) { showError(error); }
        };
        controls.append(name, vault, create);
        (app.credentials || []).forEach(credential => {
          const credentialLine = document.createElement('div');
          credentialLine.className = 'credential-line';
          const label = document.createElement('span');
          label.textContent = `${credential.display_name || 'client secret'} · ${credential.key_id} · expires ${credential.expires_at ? new Date(credential.expires_at).toLocaleDateString() : 'unknown'}`;
          credentialLine.append(label);
          const read = document.createElement('button');
          read.className = 'button button-small';
          read.textContent = 'Read vault value';
          read.disabled = !document.getElementById('vault-enabled').checked && !credential.vault;
          read.onclick = async () => {
            try {
              const body = await json('/api/v1/integration/secrets/read', {method: 'POST', body: JSON.stringify({application_object_id: app.object_id, key_id: credential.key_id, version: credential.vault?.version || ''})});
              showSecret(body.secret, 'Vault secret retrieved' + receipt(body.receipt));
            } catch (error) { showError(error); }
          };
          const invalidate = document.createElement('button');
          invalidate.className = 'button button-small button-danger';
          invalidate.textContent = 'Invalidate';
          invalidate.onclick = async () => {
            if (!confirm('Invalidate this Entra client secret?')) return;
            try {
              const body = await json('/api/v1/integration/secrets/invalidate', {method: 'POST', body: JSON.stringify({application_object_id: app.object_id, key_id: credential.key_id, version: credential.vault?.version || ''})});
              output.classList.remove('is-hidden');
              output.textContent = `Credential ${body.credential.key_id} invalidated${receipt(body.receipt)}`;
              await loadApps();
            } catch (error) { showError(error); }
          };
          credentialLine.append(read, invalidate);
          controls.append(credentialLine);
        });
        card.append(controls);
      }
      list.append(card);
    });
  };
  const loadApps = async () => {
    try {
      const body = await json('/api/v1/integration/applications');
      renderApps(body.applications);
    } catch (error) { showError(error); }
  };
  document.getElementById('vault-enabled').addEventListener('change', event => document.getElementById('vault-fields').classList.toggle('is-hidden', !event.target.checked));
  form.addEventListener('submit', async event => {
    event.preventDefault();
    status.textContent = 'Connecting and validating Graph permission…';
    status.className = 'form-status';
    const data = new FormData(form);
    const request = {tenant_id: data.get('tenant_id'), client_id: data.get('client_id'), client_secret: data.get('client_secret')};
    if (data.get('vault_enabled')) {
      request.vault = {url: data.get('vault_url'), secret_prefix: data.get('secret_prefix'), owner_object_ids: String(data.get('owner_object_ids') || '').split(',').map(value => value.trim()).filter(Boolean)};
    }
    try {
      const body = await json('/api/v1/integration/connect', {method: 'POST', body: JSON.stringify(request)});
      form.reset();
      document.getElementById('vault-fields').classList.add('is-hidden');
      workspace.classList.remove('is-hidden');
      document.getElementById('session-summary').textContent = `Connected to ${body.session.tenant_hint}; session expires ${new Date(body.session.expires_at).toLocaleTimeString()}. Client secret input cleared.`;
      status.textContent = 'Connected. Only owned applications can be changed.';
      await loadApps();
    } catch (error) {
      form.querySelector('[name="client_secret"]').value = '';
      showError(error);
    }
  });
  document.getElementById('create-application-button').addEventListener('click', async () => {
    const name = document.getElementById('new-application-name').value;
    try {
      await json('/api/v1/integration/applications', {method: 'POST', body: JSON.stringify({display_name: name})});
      document.getElementById('new-application-name').value = '';
      await loadApps();
    } catch (error) { showError(error); }
  });
  document.getElementById('disconnect-button').addEventListener('click', async () => {
    try {
      await json('/api/v1/integration/disconnect', {method: 'POST', body: '{}'});
      workspace.classList.add('is-hidden');
      list.replaceChildren();
      status.textContent = 'Disconnected; in-memory credentials cleared.';
    } catch (error) { showError(error); }
  });
})();
