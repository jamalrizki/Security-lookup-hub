import { test } from 'node:test';
import assert from 'node:assert/strict';
import { attribute } from '../scripts/attribution.js';

// Sentences taken from MITRE ATT&CK v20 group descriptions.
const cases = [
  ['APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group.', ['China']],
  ['HAFNIUM is a likely state-sponsored cyber espionage group operating out of China that has been active since at least January 2021.', ['China']],
  ["Volt Typhoon is a People's Republic of China (PRC) state-sponsored actor that has been active since at least 2021.", ['China']],
  ["APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR).", ['Russia']],
  ["MuddyWater is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS).", ['Iran']],
  ["Kimsuky is a Democratic People's Republic of Korea (DPRK)-based cyber espionage group that has been active since at least 2012.", ['North Korea']],
  ['Fox Kitten is threat actor with a suspected nexus to the Iranian government that has been active since at least 2017.', ['Iran']],
  // Victim countries must not count as attribution.
  ['Strider is a threat group that has been active since at least 2011 and has targeted victims in Russia, China, Sweden, Belgium, Iran, and Rwanda.', []],
  ['TA459 is a threat group believed to operate out of China that has targeted countries including Russia, Belarus, Mongolia, and others.', ['China']],
  ['SideCopy is a Pakistani threat group that has primarily targeted South Asian countries, including Indian and Afghani government personnel.', ['Pakistan']],
  ['APT37 is a North Korean state-sponsored cyber espionage group. The group has targeted victims primarily in South Korea, but also in Japan, Vietnam, Russia, Nepal, China, India.', ['North Korea']],
  // Language alone is not attribution.
  ['Nomadic Octopus is a Russian-speaking cyber espionage threat group that has primarily targeted Central Asia.', []],
  ['FIN7 is a financially-motivated threat group that has been active since 2013.', []],
];

for (const [sentence, expected] of cases) {
  test(sentence.slice(0, 60), () => {
    assert.deepEqual(attribute(sentence).countries, expected);
  });
}
