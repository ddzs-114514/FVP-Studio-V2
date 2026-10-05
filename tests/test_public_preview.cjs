// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ddzs-114514 and FVP Studio contributors
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'web/fvp_story_studio_prototype.html'), 'utf8');
assert(!/[A-Z]:[/\\]/.test(html), 'Machine-specific absolute path remains');
assert(!/data:(?:image|audio|video)/.test(html), 'Embedded media remains');
assert(!/"source_hcb"\s*:|"source_exe"\s*:/.test(html), 'Registered game evidence remains');
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)];
assert.equal(scripts.length, 1);
new vm.Script(scripts[0][1], {filename: 'public-preview.js'});

// Evaluate the editor's actual model/parser without DOM initialisation, network
// requests, file pickers, a game, native code, or registered local sources.
const model = scripts[0][1].replace(/\binit\(\);\s*$/, '');
const checks = `
  const blankResult = parseProjectText(JSON.stringify(blankProjectDoc('合成空白工程', '第一章')));
  if (!blankResult.ok) throw Error(JSON.stringify(blankResult.errors));
  useProjectData(blankResult.data);
  const exported = projectDoc();
  const roundtrip = parseProjectText(JSON.stringify(exported));
  if (!roundtrip.ok) throw Error('Blank project roundtrip failed');
  if (P.cast.length || Object.keys(P.externalGraphics).length || Object.keys(P.externalSources).length)
    throw Error('Blank project contains registered assets');
  const broken = JSON.parse(JSON.stringify(exported));
  broken.project.scenes['story-scene-0001'].exit = {type:'jump', target:'missing-scene'};
  if (parseProjectText(JSON.stringify(broken)).ok) throw Error('Dangling scene accepted');
  const embedded = JSON.parse(JSON.stringify(exported));
  embedded.project.title = 'data:image/png;base64,AAAA';
  if (parseProjectText(JSON.stringify(embedded)).ok) throw Error('Embedded media accepted');
  const example = JSON.parse(exampleText);
  if (!parseProjectText(JSON.stringify(example)).ok) throw Error('Shipped blank example invalid');
`;
vm.runInNewContext(model + checks, {
  console,
  setTimeout: () => {throw Error('Unexpected timer during model-only check');},
  clearTimeout: () => {},
  exampleText: fs.readFileSync(path.join(root, 'examples/blank_project.json'), 'utf8')
}, {timeout: 10000});
console.log('PASS: JavaScript syntax, blank roundtrip, asset isolation, dangling route and embedded-media rejection');
