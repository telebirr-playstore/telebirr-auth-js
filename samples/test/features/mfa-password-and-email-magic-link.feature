Feature: Multi-Factor Authentication with Password and Email Magic Link

  Background:
    Given an App
      And the app has Email Verification callback uri defined
      And a Policy that defines "Authentication"
      And with a Policy Rule that defines "Password + Another Factor"
      And a user named "Mary"
      And she has an account with "active" state in the org

  Scenario: 2FA Login with Email Magic Link on the same browser
    Given Mary navigates to the Basic Login View
      And she has inserted her username
      And she has inserted her password
      And her password is correct
    When she clicks Login
    Then she is presented with an option to select Email to verify
    When She selects Email from the list
      And She selects "Receive a Code"
      And she clicks the Email magic link
    Then she is redirected to the Root View
      And an application session is created  
