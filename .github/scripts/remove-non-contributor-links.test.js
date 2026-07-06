'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  isNonContributor,
  containsLinks,
  removeLinks,
  run
} = require('./remove-non-contributor-links');

test('isNonContributor correctly classifies author associations', () => {
  assert.equal(isNonContributor('OWNER'), false);
  assert.equal(isNonContributor('MEMBER'), false);
  assert.equal(isNonContributor('COLLABORATOR'), false);
  assert.equal(isNonContributor('CONTRIBUTOR'), false);

  assert.equal(isNonContributor('NONE'), true);
  assert.equal(isNonContributor('FIRST_TIMER'), true);
  assert.equal(isNonContributor('FIRST_TIME_CONTRIBUTOR'), true);
  assert.equal(isNonContributor(undefined), true);
  assert.equal(isNonContributor(null), true);
});

test('containsLinks detects raw, markdown, HTML, and reference links', () => {
  assert.equal(containsLinks('Check out http://malicious-virus-site.com now!'), true);
  assert.equal(containsLinks('Check out https://virus-link.org/download'), true);
  assert.equal(containsLinks('Visit [free money](https://phishing-site.xyz/login)'), true);
  assert.equal(containsLinks('<a href="https://bad-link.com">Click here</a>'), true);
  assert.equal(containsLinks('[ref]: http://spam-site.com'), true);
  assert.equal(containsLinks('Go to www.virus-downloads.net'), true);

  assert.equal(containsLinks('Here is issue #123 and PR #45'), false);
  assert.equal(containsLinks('Plain text description without any URLs'), false);
  assert.equal(containsLinks(''), false);
  assert.equal(containsLinks(null), false);
});

test('removeLinks sanitizes all link formats and appends security notice', () => {
  const markdownText = 'Please visit [my website](https://malicious.com) for updates.';
  const markdownResult = removeLinks(markdownText);
  assert.equal(markdownResult.includes('https://malicious.com'), false);
  assert.equal(markdownResult.includes('my website [link removed for security]'), true);
  assert.equal(markdownResult.includes('Security Notice:'), true);

  const rawUrlText = 'Download virus here: http://danger.xyz/app.exe and https://badsite.org';
  const rawUrlResult = removeLinks(rawUrlText);
  assert.equal(rawUrlResult.includes('http://danger.xyz/app.exe'), false);
  assert.equal(rawUrlResult.includes('https://badsite.org'), false);
  assert.equal(rawUrlResult.includes('[link removed for security]'), true);

  const htmlText = 'Click <a href="https://phishing.com/login">here to login</a>';
  const htmlResult = removeLinks(htmlText);
  assert.equal(htmlResult.includes('https://phishing.com/login'), false);
  assert.equal(htmlResult.includes('here to login [link removed for security]'), true);
});

test('run skips processing when author is a trusted contributor', async () => {
  let updateCommentCalled = false;

  const mockGithub = {
    rest: {
      issues: {
        updateComment: async () => {
          updateCommentCalled = true;
        }
      }
    }
  };

  const mockContext = {
    repo: { owner: 'test-owner', repo: 'test-repo' },
    payload: {
      comment: {
        id: 101,
        author_association: 'MEMBER',
        body: 'Here is a link: https://official-docs.com'
      }
    }
  };

  const mockCore = {
    info: () => {}
  };

  await run({ github: mockGithub, context: mockContext, core: mockCore });
  assert.equal(updateCommentCalled, false);
});

test('run updates issue comment when non-contributor posts links', async () => {
  let updatedCommentBody = '';

  const mockGithub = {
    rest: {
      issues: {
        updateComment: async ({ comment_id, body }) => {
          assert.equal(comment_id, 202);
          updatedCommentBody = body;
        }
      }
    }
  };

  const mockContext = {
    repo: { owner: 'test-owner', repo: 'test-repo' },
    payload: {
      comment: {
        id: 202,
        author_association: 'NONE',
        body: 'Hey download this file from http://virus-link.com/file.exe'
      }
    }
  };

  const mockCore = {
    info: () => {}
  };

  await run({ github: mockGithub, context: mockContext, core: mockCore });

  assert.equal(updatedCommentBody.includes('http://virus-link.com/file.exe'), false);
  assert.equal(updatedCommentBody.includes('[link removed for security]'), true);
  assert.equal(updatedCommentBody.includes('Security Notice:'), true);
});

test('run updates issue body when non-contributor opens/edits issue with links', async () => {
  let updatedIssueBody = '';

  const mockGithub = {
    rest: {
      issues: {
        update: async ({ issue_number, body }) => {
          assert.equal(issue_number, 55);
          updatedIssueBody = body;
        }
      }
    }
  };

  const mockContext = {
    repo: { owner: 'test-owner', repo: 'test-repo' },
    payload: {
      issue: {
        number: 55,
        author_association: 'FIRST_TIMER',
        body: 'Report bug at [site](https://fake-support.com) or go to www.phishing.com'
      }
    }
  };

  const mockCore = {
    info: () => {}
  };

  await run({ github: mockGithub, context: mockContext, core: mockCore });

  assert.equal(updatedIssueBody.includes('https://fake-support.com'), false);
  assert.equal(updatedIssueBody.includes('www.phishing.com'), false);
  assert.equal(updatedIssueBody.includes('[link removed for security]'), true);
});

test('run updates PR body when non-contributor opens/edits PR with links', async () => {
  let updatedPrBody = '';

  const mockGithub = {
    rest: {
      pulls: {
        update: async ({ pull_number, body }) => {
          assert.equal(pull_number, 77);
          updatedPrBody = body;
        }
      }
    }
  };

  const mockContext = {
    repo: { owner: 'test-owner', repo: 'test-repo' },
    payload: {
      pull_request: {
        number: 77,
        author_association: 'FIRST_TIME_CONTRIBUTOR',
        body: 'See screenshot here: https://untrusted-image-host.net/pic.png'
      }
    }
  };

  const mockCore = {
    info: () => {}
  };

  await run({ github: mockGithub, context: mockContext, core: mockCore });

  assert.equal(updatedPrBody.includes('https://untrusted-image-host.net/pic.png'), false);
  assert.equal(updatedPrBody.includes('[link removed for security]'), true);
});
