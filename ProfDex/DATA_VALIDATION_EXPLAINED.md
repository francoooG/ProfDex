# DATA_VALIDATION_2.3.1_EXPLAINED.md

## Changes Implemented

### 1. Input Rejection (No Sanitization)

#### First Name & Last Name
**Code:**
```javascript
const nameRegex = /^[A-Za-z\-\' ]+$/;
if (!firstName || !nameRegex.test(firstName)) {
  alert('Invalid first name.');
  return;
}
if (!lastName || !nameRegex.test(lastName)) {
  alert('Invalid last name.');

  # DATA_VALIDATION_2.3.1_EXPLAINED.md

  ## Overview
  This document explains the comprehensive data validation logic implemented across multiple forms in the ProfDex project. All validation failures result in input rejection, and no sanitizing is performed.

  ## Changes Implemented (by file)

  ### LR_page.hbs (Registration)
  - First Name & Last Name: Only letters, hyphens, apostrophes, and spaces. Required.
  - Email: Must match a valid email format. Required.
  - Student ID: Only 1-8 digits. Required for students.
  - Password: Strict requirements (length, uppercase, lowercase, number, special character, complexity, no sequences, no repeats, no patterns, not common). All requirements must be met.
  - All validation failures block form submission and show an error.

  ### viewreview.hbs (Comments)
  - Comment: Must match `/^[\p{L}\p{N}\p{P}\p{Zs}\n\r]{1,2000}$/u` (letters, numbers, punctuation, spaces, newlines, 1-2000 chars). No `<` or `>` allowed. Invalid input is rejected.

  ### editprofile_page.hbs (Edit Profile)
  - First/Last Name: Only letters, hyphens, apostrophes, and spaces. Required.
  - Email: Must match a valid email format. Required.
  - Student ID: Only 1-8 digits. Required for students.
  - Course: Must be selected if present.
  - Bio: Max 300 characters, only letters and spaces allowed.
  - All validation failures block form submission and show an error.

  ### createpost.hbs (Create Review)
  - Professor: Must be selected.
  - Course: Must be selected.
  - Ratings (proficiency, generosity, engagement, workload, difficulty): Each must be between 1 and 5.
  - Review Text: 10-2000 characters, no `<` or `>`. Invalid input is rejected.

  ### editreview.hbs (Edit Review)
  - Ratings (proficiency, generosity, engagement, workload, difficulty): Each must be between 1 and 5.
  - Review Text: 10-2000 characters, no `<` or `>`. Invalid input is rejected.

  ### professor_search.hbs (Search Bar)
  - Search input: Only letters, spaces, hyphens, apostrophes, max 100 characters. Required. Invalid input is rejected.

  ### setup_security_questions.hbs (Security Questions)
  - Each question must be selected.
  - Each answer: 1-100 characters, only letters, numbers, spaces, hyphens, apostrophes. Invalid input is rejected.

  ## Example Code Snippets

  ### Registration (LR_page.hbs)
  ```javascript
  const nameRegex = /^[A-Za-z\-\' ]+$/;
  if (!firstName || !nameRegex.test(firstName)) { alert('Invalid first name.'); e.preventDefault(); return false; }
  if (!lastName || !nameRegex.test(lastName)) { alert('Invalid last name.'); e.preventDefault(); return false; }
  if (!email || !/^([a-zA-Z0-9_\-.+]+)@([a-zA-Z0-9_\-.]+)\.([a-zA-Z]{2,})$/.test(email)) { alert('Invalid email address.'); e.preventDefault(); return false; }
  const studentIdRegex = /^\d{1,8}$/;
  if (!studentID || !studentIdRegex.test(studentID)) { alert('Student ID must be at most 8 digits and only numbers.'); e.preventDefault(); return false; }
  // Password validation uses validatePassword() and blocks submission if requirements are not met.
  ```

  ### Comments (viewreview.hbs)
  ```javascript
  var commentRegex = /^[\p{L}\p{N}\p{P}\p{Zs}\n\r]{1,2000}$/u;
  if (!commentRegex.test(comment)) { alert('Comment rejected: must be 1-2000 valid characters.'); e.preventDefault(); return false; }
  ```

  ### Edit Profile (editprofile_page.hbs)
  ```javascript
  var bioRegex = /^[A-Za-z\s]{0,300}$/;
  if (bio.length > 300 || !bioRegex.test(bio)) { alert('Bio must be at most 300 characters and only contain letters and spaces.'); e.preventDefault(); return false; }
  ```

  ### Create/Edit Review (createpost.hbs, editreview.hbs)
  ```javascript
  var reviewRegex = /^[^<>]{10,2000}$/;
  if (!reviewRegex.test(reviewText)) { alert('Review must be 10-2000 characters and not contain < or >.'); e.preventDefault(); return false; }
  ```

  ### Professor Search (professor_search.hbs)
  ```javascript
  var searchRegex = /^[A-Za-z\-\' ]{1,100}$/;
  if (!searchInput || !searchRegex.test(searchInput)) { alert('Please enter a valid professor name.'); e.preventDefault(); return false; }
  ```

  ### Security Questions (setup_security_questions.hbs)
  ```javascript
  var answerRegex = /^[A-Za-z0-9\-\' ]{1,100}$/;
  if (!aVal || !answerRegex.test(aVal)) { alert('Invalid answer.'); e.preventDefault(); return false; }
  ```

  ## Rationale
  These changes ensure that only strictly valid data is accepted for all user input forms, improving data integrity and security. All validation failures result in input rejection, not sanitization.

  ## Location of Changes
  All validation logic is implemented in the client-side JavaScript within the respective `.hbs` view files.

  ## Summary
  All major forms and input fields in ProfDex now strictly enforce validation, rejecting any invalid input and preventing form submission until all requirements are met.
      e.preventDefault();
