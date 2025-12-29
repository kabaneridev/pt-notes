# Skills Assessment

This section outlines a skills assessment for the "Session Puzzling" module, requiring students to identify and exploit various session puzzling vulnerabilities to gain unauthorized access or elevate privileges within a web application.

## Walkthrough

After logging in with the credentials `htb-stdnt:Academy_student!`, students need to navigate to the password reset functionality at `/reset_1.php` and supply the username `admin`, then click on Submit.

Students should not complete phase 2 of the password reset process. Instead, they need to navigate directly to `/admin_users.php` to exploit premature session value population, which will grant them access to the admin panel.


