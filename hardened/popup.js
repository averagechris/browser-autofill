const $ = id => document.getElementById(id);
let busy = false;
let origin = '';
let pending = null;

async function request(message) {
  const result = await chrome.runtime.sendMessage(message);
  if (!result?.ok) throw new Error(result?.error || 'Reopen the popup to try again.');
  return result;
}

async function action(task, status = $('status')) {
  if (busy) return;
  busy = true;
  for (const button of document.querySelectorAll('button')) button.disabled = true;
  try {
    await task();
  } catch (error) {
    status.textContent = String(error.message || 'Unable to complete this action.').slice(0, 180);
    if (status === $('status')) $('retry').hidden = false;
  } finally {
    busy = false;
    for (const button of document.querySelectorAll('button')) button.disabled = false;
  }
}

function showAccounts(list, items) {
  list.replaceChildren();
  for (const item of items) {
    const row = document.createElement('li');
    const button = document.createElement('button');
    const title = document.createElement('strong');
    const details = document.createElement('small');
    title.textContent = item.title || 'Account';
    details.textContent = [item.username, item.savedOrigin || (item.requiresConfirmation ? 'No saved HTTPS site' : '')].filter(Boolean).join(' · ');
    button.append(title, details);
    button.addEventListener('click', () => {
      if (busy) return;
      if (item.requiresConfirmation) {
        pending = item;
        $('destination').textContent = `Fill this account on ${origin}? Saved site: ${item.savedOrigin || 'unavailable'}.`;
        $('confirmation').hidden = false;
        $('confirm').focus();
        $('confirmation').scrollIntoView({ block: 'nearest' });
      } else {
        fill(item);
      }
    });
    row.append(button);
    list.append(row);
  }
}

function cancelConfirmation() {
  pending = null;
  $('confirmation').hidden = true;
}

function fill(item, confirmOrigin) {
  cancelConfirmation();
  action(async () => {
    await request({ type: 'fill', token: item.token, confirmOrigin });
    window.close();
  });
}

function loadMatches() {
  cancelConfirmation();
  action(async () => {
    $('retry').hidden = true;
    $('status').textContent = 'Loading matching accounts…';
    $('results').replaceChildren();
    const result = await request({ type: 'lookup' });
    origin = result.context.origin;
    $('site').textContent = origin;
    showAccounts($('matches'), result.items);
    $('status').textContent = result.unlockedCount === 0
      ? 'Unlock a browser-enabled database in Strongbox.'
      : result.items.length ? '' : 'No matching accounts for this site.';
    $('retry').hidden = result.unlockedCount !== 0;
  });
}

$('retry').addEventListener('click', loadMatches);
$('confirm').addEventListener('click', () => { if (pending) fill(pending, origin); });
$('cancel').addEventListener('click', cancelConfirmation);
$('finder').addEventListener('toggle', () => {
  if ($('finder').open) $('query').focus();
  else cancelConfirmation();
});
$('search').addEventListener('submit', event => {
  event.preventDefault();
  cancelConfirmation();
  action(async () => {
    $('search-status').textContent = 'Searching…';
    $('results').replaceChildren();
    const result = await request({ type: 'search', query: $('query').value });
    origin = result.context.origin;
    $('site').textContent = origin;
    showAccounts($('results'), result.items);
    $('search-status').textContent = result.limited
      ? 'Partial results. Try a longer part of the account name.'
      : result.items.length ? '' : 'No accounts found by name.';
  }, $('search-status'));
});
loadMatches();
