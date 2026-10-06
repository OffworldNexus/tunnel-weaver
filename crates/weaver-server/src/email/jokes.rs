//! A small embedded joke library for the temporary `send-a-joke` dev verb.
//!
//! DELETED alongside the verb once real account email ships (OFF-194/OFF-191).

use rand::seq::IndexedRandom;

/// Clean, work-safe one-liners used by the development template.
pub const JOKES: &[&str] = &[
    "Why do programmers prefer dark mode? Because light attracts bugs.",
    "There are only two hard things in computing: cache invalidation, naming things, and off-by-one errors.",
    "A SQL query walks into a bar, approaches two tables and asks: may I join you?",
    "Why did the developer go broke? Because they used up all their cache.",
    "I would tell you a UDP joke, but you might not get it.",
    "Debugging: being the detective in a crime movie where you are also the murderer.",
    "It works on my machine. Then we will ship your machine.",
    "Why do Java developers wear glasses? Because they do not C sharp.",
    "A byte walks into a bar. The bartender asks: what will it be? The byte says: bit.",
    "There is no place like 127.0.0.1.",
];

/// Picks a random joke line, falling back to the first if the library is empty.
pub fn pick() -> &'static str {
    JOKES.choose(&mut rand::rng()).copied().unwrap_or(JOKES[0])
}
