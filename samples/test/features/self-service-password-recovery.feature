Feature: Direct Auth Password Recovery

Background:
  Given an App
    And a Policy that defines "Authentication"
    And with a Policy Rule that defines "Password as the only factor"
    And a user named "Mary"
    And she has an account with "active" state in the org

  Scenario: Mary resets her password
    Given Mary navigates to the Self Service Password Reset View
    When she inputs her correct Email
    And she submits the recovery form
    Then she sees a page to select authenticator
    And password authenticator is not in options
    When she selects email authenticator
    And she submits the form
    Then she sees a page to challenge her email authenticator
    When she fills in the correct code
    And she submits the form
    Then she sees a page to set her password
    When she fills a password that fits within the password policy
    And she confirms that password
    And she submits the form
    Then she is redirected to the Root Page

  Scenario: Mary tries to reset a password with the wrong email
    Given the app is assigned to "Everyone" group
      And Mary navigates to the Self Service Password Reset View
    When she inputs an Email that doesn't exist
    And she submits the form
    Then she should see the message "There is no account with the Username test_with_really_invalid_email@invalidemail.com."
