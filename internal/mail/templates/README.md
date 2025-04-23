# Email Templates

This directory contains all email templates used by the CService API. Each template consists of both HTML and plain text versions to support all email clients.

## Directory Structure

-   `default/` - Default template used when a specific template is not found
-   `registration/` - Template for account registration and activation
-   `assets/` - Images and other static assets used in emails

## Creating a New Template

To create a new template:

1. Create a new directory under `templates/mail/` with the name of your template (e.g., `password_reset`)
2. Create two template files in the directory:
    - `html.tmpl` - HTML version of the email
    - `text.tmpl` - Plain text version of the email

Both templates should be valid Go templates and receive the same context data.

## Template Variables

Each template receives a data context with variables that can be used in the template. The available variables depend on the type of email being sent.

### Common Variables

These variables are available in all templates:

-   `{{.Year}}` - Current year (used in copyright notices)

### Registration Template

-   `{{.Username}}` - The username of the new user
-   `{{.ActivationURL}}` - The activation URL for the account

## Images in Templates

To embed images in your email templates:

1. Reference the image in your HTML using: `<img src="cid:image_id">`
2. When sending the email, include the image in the `Images` field of the `Mail` struct:

```go
mail := &mail.Mail{
    // ... other fields ...
    Template: "my_template",
    Images: []mail.EmbeddedImage{
        {
            ContentID: "image_id",
            Path:      "/path/to/image.png",
        },
    },
}
```

## Overriding Templates

You can override which template to use by setting the appropriate configuration in `config.go`. The default template directory is `templates/mail` and can be changed with:

```
service.mail.template_dir=/path/to/custom/templates
```

The default template (used when a requested template doesn't exist) is set with:

```
service.mail.default_template=default
```
