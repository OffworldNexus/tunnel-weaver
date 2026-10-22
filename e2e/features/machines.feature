@machines
Feature: Live machine status in the console

  The console keeps itself current: every list and detail view is also an SSE
  stream, so a change made anywhere — another tab, another device — reaches the
  screen without a reload. The stream is literally the same resource as the JSON
  call, re-sent in full whenever it changes.

  Background:
    Given a unique email address for "Ada Lovelace"

  Scenario: A change made in another tab reaches the machines list without a reload
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given the machine "laptop" is paired
    When I open the machines page
    Then I see the machine "laptop" in the list
    When in another tab I rename "laptop" to "laptop2"
    Then the machine "laptop2" appears here without a reload

  # The transport contract, exercised directly: the URL answers the JSON call
  # once, and answers the same body again on every change.
  Scenario: The machines URL is the JSON call once, or a stream of every change
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given the machine "laptop" is paired
    When I stream the machines URL and rename "laptop" to "laptop2"
    Then the stream's first frame matches the JSON call
    And a later frame carries "laptop2"
