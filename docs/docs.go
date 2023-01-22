// Package docs GENERATED BY SWAG; DO NOT EDIT
// This file was generated by swaggo/swag
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Ratler",
            "email": "ratler@undernet.org"
        },
        "license": {
            "name": "MIT",
            "url": "https://github.com/UndernetIRC/cservice-api/blob/master/LICENSE"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/authn": {
            "post": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "accounts"
                ],
                "summary": "Authenticate user to retrieve JWT token",
                "parameters": [
                    {
                        "description": "Login request",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/controllers.loginRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/controllers.loginResponse"
                        }
                    },
                    "401": {
                        "description": "Invalid username or password"
                    }
                }
            }
        },
        "/authn/logout": {
            "post": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "accounts"
                ],
                "summary": "Logout user",
                "parameters": [
                    {
                        "description": "Logout request",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/controllers.logoutRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Logged out",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad request",
                        "schema": {
                            "$ref": "#/definitions/controllers.customError"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/controllers.customError"
                        }
                    }
                }
            }
        },
        "/authn/refresh": {
            "post": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "accounts"
                ],
                "summary": "Request new session tokens using a Refresh JWT token",
                "parameters": [
                    {
                        "description": "Refresh token",
                        "name": "data",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/controllers.refreshTokenRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/controllers.loginResponse"
                        }
                    },
                    "400": {
                        "description": "Bad request",
                        "schema": {
                            "$ref": "#/definitions/controllers.customError"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "$ref": "#/definitions/controllers.customError"
                        }
                    }
                }
            }
        },
        "/me": {
            "get": {
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "accounts"
                ],
                "summary": "Get detailed information about the current user",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/controllers.MeResponse"
                        }
                    },
                    "401": {
                        "description": "Authorization information is missing or invalid."
                    }
                }
            }
        }
    },
    "definitions": {
        "controllers.MeChannelResponse": {
            "type": "object",
            "properties": {
                "access": {
                    "type": "integer"
                },
                "channel_id": {
                    "type": "integer"
                },
                "last_modified": {
                    "type": "integer"
                },
                "name": {
                    "type": "string"
                }
            }
        },
        "controllers.MeResponse": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer",
                    "x-order": "0"
                },
                "username": {
                    "type": "string",
                    "x-order": "1"
                },
                "email": {
                    "type": "string",
                    "x-order": "2"
                },
                "max_logins": {
                    "type": "integer",
                    "x-order": "3"
                },
                "language_code": {
                    "type": "string",
                    "x-order": "4"
                },
                "language_name": {
                    "type": "string",
                    "x-order": "5"
                },
                "last_seen": {
                    "type": "integer",
                    "x-order": "6"
                },
                "channels": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/controllers.MeChannelResponse"
                    },
                    "x-order": "7"
                }
            }
        },
        "controllers.customError": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "integer"
                },
                "message": {
                    "type": "string"
                }
            }
        },
        "controllers.loginRequest": {
            "type": "object",
            "required": [
                "password",
                "username"
            ],
            "properties": {
                "username": {
                    "type": "string",
                    "maxLength": 12,
                    "minLength": 2,
                    "x-order": "0"
                },
                "password": {
                    "type": "string",
                    "x-order": "1"
                }
            }
        },
        "controllers.loginResponse": {
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string",
                    "x-order": "0"
                },
                "refresh_token": {
                    "type": "string",
                    "x-order": "1"
                }
            }
        },
        "controllers.logoutRequest": {
            "type": "object",
            "properties": {
                "logout_all": {
                    "type": "boolean"
                }
            }
        },
        "controllers.refreshTokenRequest": {
            "type": "object",
            "properties": {
                "refresh_token": {
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "0.1",
	Host:             "localhost:8080",
	BasePath:         "/api/v1",
	Schemes:          []string{},
	Title:            "UnderNET Channel Service API",
	Description:      "...",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
