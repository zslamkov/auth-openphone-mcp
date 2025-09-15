{
  "openapi": "3.1.0",
  "info": {
    "title": "OpenPhone Public API",
    "version": "1.0.0",
    "description": "API for connecting with OpenPhone.",
    "contact": {
      "name": "OpenPhone Support",
      "email": "support@openphone.com",
      "url": "https://support.openphone.com/hc/en-us"
    },
    "termsOfService": "https://www.openphone.com/terms"
  },
  "paths": {
    "/v1/calls": {
      "get": {
        "tags": [
          "Calls"
        ],
        "summary": "List calls",
        "description": "Fetch a paginated list of calls associated with a specific OpenPhone number and another number.",
        "operationId": "listCalls_v1",
        "parameters": [
          {
            "in": "query",
            "name": "phoneNumberId",
            "required": true,
            "schema": {
              "description": "The unique identifier of the OpenPhone number associated with the call.",
              "examples": [
                "PN123abc"
              ],
              "pattern": "^PN(.*)$",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "userId",
            "required": false,
            "schema": {
              "description": "The unique identifier of the OpenPhone user who either placed or received the call. Defaults to the workspace owner.",
              "examples": [
                "US123abc"
              ],
              "pattern": "^US(.*)$",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "participants",
            "required": true,
            "schema": {
              "maxItems": 1,
              "description": "The phone numbers of participants involved in the call conversation, excluding your OpenPhone number. Each number should contain the country code and conform to the E.164 format. Currently limited to one-to-one (1:1) conversations only.",
              "examples": [
                "+15555555555"
              ],
              "type": "array",
              "items": {
                "minLength": 1,
                "type": "string"
              }
            }
          },
          {
            "in": "query",
            "name": "since",
            "required": false,
            "schema": {
              "deprecated": true,
              "description": "DEPRECATED, use \"createdAfter\" or \"createdBefore\" instead. \"since\" incorrectly behaves as \"createdBefore\" and will be removed in an upcoming release.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "createdAfter",
            "required": false,
            "schema": {
              "description": "Filter results to only include calls created after the specified date and time, in ISO 8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "createdBefore",
            "required": false,
            "schema": {
              "description": "Filter results to only include calls created before the specified date and time, in ISO 8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "maxResults",
            "required": true,
            "schema": {
              "description": "Maximum number of results to return per page.",
              "default": 10,
              "maximum": 100,
              "minimum": 1,
              "type": "integer"
            }
          },
          {
            "in": "query",
            "name": "pageToken",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "additionalProperties": false,
                        "type": "object",
                        "properties": {
                          "answeredAt": {
                            "anyOf": [
                              {
                                "description": "The timestamp when the call was answered in ISO 8601 format. Null if the call was not answered.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "answeredBy": {
                            "anyOf": [
                              {
                                "description": "The unique identifier of the OpenPhone user who answered the incoming call. Null for outgoing calls or unanswered incoming calls.",
                                "examples": [
                                  "USlHhXmRMz"
                                ],
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "initiatedBy": {
                            "anyOf": [
                              {
                                "description": "The unique identifier of the OpenPhone user who initiated the outgoing call. Null for incoming calls.",
                                "examples": [
                                  "USlHhXmRMz"
                                ],
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "direction": {
                            "type": "string",
                            "enum": [
                              "incoming",
                              "outgoing"
                            ],
                            "description": "The direction of the call relative to the OpenPhone number.",
                            "examples": [
                              "incoming"
                            ]
                          },
                          "status": {
                            "type": "string",
                            "enum": [
                              "queued",
                              "initiated",
                              "ringing",
                              "in-progress",
                              "completed",
                              "busy",
                              "failed",
                              "no-answer",
                              "canceled",
                              "missed",
                              "answered",
                              "forwarded",
                              "abandoned"
                            ],
                            "description": "The current status of the call.",
                            "examples": [
                              "completed"
                            ]
                          },
                          "completedAt": {
                            "anyOf": [
                              {
                                "description": "The timestamp when the call ended, in ISO 8601 format. Null if the call is ongoing or was not completed.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "createdAt": {
                            "description": "The timestamp when the call record was created, in ISO 8601 format.",
                            "examples": [
                              "2022-01-01T00:00:00Z"
                            ],
                            "format": "date-time",
                            "type": "string"
                          },
                          "duration": {
                            "description": "The total duration of the call in seconds.",
                            "examples": [
                              60
                            ],
                            "type": "integer"
                          },
                          "forwardedFrom": {
                            "anyOf": [
                              {
                                "anyOf": [
                                  {
                                    "pattern": "^\\+[1-9]\\d{1,14}$",
                                    "description": "A phone number in E.164 format, including the country code.",
                                    "examples": [
                                      "+15555555555"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "pattern": "^US(.*)$",
                                    "type": "string"
                                  }
                                ]
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "forwardedTo": {
                            "anyOf": [
                              {
                                "anyOf": [
                                  {
                                    "pattern": "^\\+[1-9]\\d{1,14}$",
                                    "description": "A phone number in E.164 format, including the country code.",
                                    "examples": [
                                      "+15555555555"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "pattern": "^US(.*)$",
                                    "type": "string"
                                  }
                                ]
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "id": {
                            "description": "The unique identifier of the call.",
                            "examples": [
                              "AC123abc"
                            ],
                            "pattern": "^AC(.*)$",
                            "type": "string"
                          },
                          "phoneNumberId": {
                            "description": "The unique identifier of the OpenPhone number associated with the call.",
                            "examples": [
                              "PN123abc"
                            ],
                            "pattern": "^PN(.*)$",
                            "type": "string"
                          },
                          "participants": {
                            "maxItems": 2,
                            "type": "array",
                            "items": {
                              "pattern": "^\\+[1-9]\\d{1,14}$",
                              "description": "A phone number in E.164 format, including the country code.",
                              "examples": [
                                "+15555555555"
                              ],
                              "type": "string"
                            }
                          },
                          "updatedAt": {
                            "anyOf": [
                              {
                                "description": "The timestamp when the call record was last updated, in ISO 8601 format. Null if never updated.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "userId": {
                            "description": "The unique identifier of the OpenPhone user account associated with the call.",
                            "examples": [
                              "US123abc"
                            ],
                            "pattern": "^US(.*)$",
                            "type": "string"
                          }
                        },
                        "required": [
                          "answeredAt",
                          "answeredBy",
                          "initiatedBy",
                          "direction",
                          "status",
                          "completedAt",
                          "createdAt",
                          "duration",
                          "forwardedFrom",
                          "forwardedTo",
                          "id",
                          "phoneNumberId",
                          "participants",
                          "updatedAt",
                          "userId"
                        ]
                      }
                    },
                    "totalItems": {
                      "description": "Total number of items available. ⚠️ Note: `totalItems` is not accurately returning the total number of items that can be paginated. We are working on fixing this issue.",
                      "type": "integer"
                    },
                    "nextPageToken": {
                      "anyOf": [
                        {
                          "type": "string"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    }
                  },
                  "required": [
                    "data",
                    "totalItems",
                    "nextPageToken"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0100400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0100401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0101403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0100404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0101500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/call-recordings/{callId}": {
      "get": {
        "tags": [
          "Calls"
        ],
        "summary": "Get recordings for a call",
        "description": "Retrieve a list of recordings associated with a specific call. The results are sorted chronologically, with the oldest recording segment appearing first in the list.",
        "operationId": "getCallRecordings_v1",
        "parameters": [
          {
            "in": "path",
            "name": "callId",
            "required": true,
            "schema": {
              "description": "The unique identifier of the call for which recordings are being retrieved.",
              "examples": [
                "AC3700e624eca547eb9f749a06f"
              ],
              "pattern": "^AC(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "additionalProperties": false,
                        "type": "object",
                        "properties": {
                          "duration": {
                            "anyOf": [
                              {
                                "description": "The length of the call recording in seconds. Null if the recording is not completed or the duration is unknown.",
                                "examples": [
                                  60
                                ],
                                "type": "integer"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "id": {
                            "description": "The unique identifier of the call recording.",
                            "examples": [
                              "CRwRVK2qBq"
                            ],
                            "type": "string"
                          },
                          "startTime": {
                            "anyOf": [
                              {
                                "description": "The timestamp when the recording began, in ISO 8601 format. Null if the recording hasn't started or the start time is unknown.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "status": {
                            "anyOf": [
                              {
                                "type": "string",
                                "enum": [
                                  "absent",
                                  "completed",
                                  "deleted",
                                  "failed",
                                  "in-progress",
                                  "paused",
                                  "processing",
                                  "stopped",
                                  "stopping"
                                ],
                                "description": "The current status of the call recording.",
                                "examples": [
                                  "completed"
                                ]
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "type": {
                            "anyOf": [
                              {
                                "description": "The file type of the call recording. Null if the type is not specified or is unknown.",
                                "examples": [
                                  "audio/mpeg"
                                ],
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "url": {
                            "anyOf": [
                              {
                                "description": "The URL where the call recording can be accessed or downloaded. Null if the URL is not available or the recording is not accessible.",
                                "examples": [
                                  "https://examplestorage.com/a643d4d3e1484fcc8b721627284eda5e.mp3"
                                ],
                                "format": "uri-reference",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          }
                        },
                        "required": [
                          "duration",
                          "id",
                          "startTime",
                          "status",
                          "type",
                          "url"
                        ]
                      }
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0900400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0900401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0900403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0900404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0901500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/call-summaries/{callId}": {
      "get": {
        "tags": [
          "Calls"
        ],
        "summary": "Get a summary for a call",
        "description": "Retrieve an AI-generated summary of a specific call identified by its unique call ID. Call summaries are only available on OpenPhone Business plan.",
        "operationId": "getCallSummary_v1",
        "parameters": [
          {
            "in": "path",
            "name": "callId",
            "required": true,
            "schema": {
              "description": "The unique identifier of the call associated with the summary.",
              "examples": [
                "AC3700e624eca547eb9f749a06f"
              ],
              "pattern": "^AC(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "callId": {
                          "description": "The unique identifier of the call to which this summary belongs.",
                          "examples": [
                            "ACea724hac8c30465bcbcff0b76e4c1c7b"
                          ],
                          "type": "string"
                        },
                        "nextSteps": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "examples": [
                                  "Bring an umbrella."
                                ],
                                "type": "string"
                              }
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "absent",
                            "in-progress",
                            "completed",
                            "failed"
                          ],
                          "description": "The status of the call summary.",
                          "examples": [
                            "completed"
                          ]
                        },
                        "summary": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "examples": [
                                  "You talked about the weather."
                                ],
                                "type": "string"
                              }
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "jobs": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "icon": {
                                    "type": "string"
                                  },
                                  "name": {
                                    "type": "string"
                                  },
                                  "result": {
                                    "type": "object",
                                    "properties": {
                                      "data": {
                                        "type": "array",
                                        "items": {
                                          "type": "object",
                                          "properties": {
                                            "name": {
                                              "type": "string"
                                            },
                                            "value": {
                                              "anyOf": [
                                                {
                                                  "type": "string"
                                                },
                                                {
                                                  "type": "number"
                                                },
                                                {
                                                  "type": "boolean"
                                                }
                                              ]
                                            }
                                          },
                                          "required": [
                                            "name",
                                            "value"
                                          ]
                                        }
                                      }
                                    },
                                    "required": [
                                      "data"
                                    ]
                                  }
                                },
                                "required": [
                                  "icon",
                                  "name",
                                  "result"
                                ]
                              }
                            },
                            {
                              "type": "null"
                            }
                          ]
                        }
                      },
                      "required": [
                        "callId",
                        "nextSteps",
                        "status",
                        "summary"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0500400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0500401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0500403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0500404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0501500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/call-transcripts/{id}": {
      "get": {
        "tags": [
          "Calls"
        ],
        "summary": "Get a transcription for a call",
        "description": "Retrieve a detailed transcript of a specific call identified by its unique call ID. Call transcripts are only available on OpenPhone business plan.",
        "operationId": "getCallTranscript_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "Unique identifier of the call associated with this transcript.",
              "examples": [
                "AC3700e624eca547eb9f749a06f2eb1"
              ],
              "pattern": "^AC(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "callId": {
                          "description": "The unique identifier of the call to which this transcript belongs.",
                          "examples": [
                            "ACea724hac8c30465bcbcff0b76e4c1c7b"
                          ],
                          "type": "string"
                        },
                        "createdAt": {
                          "description": "The timestamp when the transcription was created, in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "dialogue": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "content": {
                                    "description": "The transcribed text of a specific dialogue segment.",
                                    "examples": [
                                      "Hello, world!"
                                    ],
                                    "type": "string"
                                  },
                                  "start": {
                                    "description": "The start time of the dialogue segment in seconds, relative to the beginning of the call.",
                                    "examples": [
                                      5.123456
                                    ],
                                    "type": "number"
                                  },
                                  "end": {
                                    "description": "The end time of the dialogue segment in seconds, relative to the beginning of the call.",
                                    "examples": [
                                      10.123456
                                    ],
                                    "type": "number"
                                  },
                                  "identifier": {
                                    "description": "The phone number of the participant who spoke during this dialogue segment.",
                                    "examples": [
                                      "+19876543210"
                                    ],
                                    "type": "string"
                                  },
                                  "userId": {
                                    "anyOf": [
                                      {
                                        "description": "The unique identifier of the OpenPhone user who spoke during this dialogue segment. Null for external participants or if user identification is not available.",
                                        "examples": [
                                          "US123abc"
                                        ],
                                        "pattern": "^US(.*)$",
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  }
                                },
                                "required": [
                                  "content",
                                  "start",
                                  "end",
                                  "identifier",
                                  "userId"
                                ]
                              }
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "duration": {
                          "description": "The total duration of the transcribed call in seconds.",
                          "examples": [
                            100
                          ],
                          "type": "number"
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "absent",
                            "in-progress",
                            "completed",
                            "failed"
                          ],
                          "description": "The status of the call transcription.",
                          "examples": [
                            "completed"
                          ]
                        }
                      },
                      "required": [
                        "callId",
                        "createdAt",
                        "dialogue",
                        "duration",
                        "status"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0600400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0600401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0600403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0600404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0601500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/contact-custom-fields": {
      "get": {
        "tags": [
          "Contact Custom Fields"
        ],
        "summary": "Get contact custom fields",
        "description": "Custom contact fields enhance your OpenPhone contacts with additional information beyond standard details like name, company, role, emails and phone numbers. These user-defined fields let you capture business-specific data. While you can only create or modify these fields in OpenPhone itself, this endpoint retrieves your existing custom properties. Use this information to accurately map and include important custom data when creating new contacts via the API.",
        "operationId": "getContactCustomFields_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "name": {
                            "description": "The name of the custom contact field. This name is set by users in the OpenPhone interface when the custom field is created.",
                            "examples": [
                              "Inbound Lead"
                            ],
                            "type": "string"
                          },
                          "key": {
                            "description": "The identifying key for contact custom field.",
                            "examples": [
                              "inbound-lead"
                            ],
                            "type": "string"
                          },
                          "type": {
                            "type": "string",
                            "enum": [
                              "address",
                              "boolean",
                              "date",
                              "multi-select",
                              "number",
                              "string",
                              "url"
                            ],
                            "description": "The data type of the custom contact field, determining what kind of information can be stored and how it should be formatted.",
                            "examples": [
                              "boolean"
                            ]
                          }
                        },
                        "required": [
                          "name",
                          "key",
                          "type"
                        ]
                      }
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0700400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0700401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0700403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0700404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0701500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/contacts": {
      "post": {
        "tags": [
          "Contacts"
        ],
        "summary": "Create a contact",
        "description": "Create a contact for a workspace.",
        "operationId": "createContact_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "defaultFields": {
                    "type": "object",
                    "properties": {
                      "company": {
                        "anyOf": [
                          {
                            "description": "The contact's company name.",
                            "examples": [
                              "OpenPhone"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "emails": {
                        "type": "array",
                        "items": {
                          "type": "object",
                          "properties": {
                            "name": {
                              "description": "The name for the contact's email address.",
                              "examples": [
                                "company email"
                              ],
                              "type": "string"
                            },
                            "value": {
                              "anyOf": [
                                {
                                  "description": "The contact's email address.",
                                  "examples": [
                                    "abc@example.com"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            }
                          },
                          "required": [
                            "name",
                            "value"
                          ]
                        }
                      },
                      "firstName": {
                        "anyOf": [
                          {
                            "description": "The contact's first name.",
                            "examples": [
                              "John"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "lastName": {
                        "anyOf": [
                          {
                            "description": "The contact's last name.",
                            "examples": [
                              "Doe"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "phoneNumbers": {
                        "type": "array",
                        "items": {
                          "type": "object",
                          "properties": {
                            "name": {
                              "description": "The name of the contact's phone number.",
                              "examples": [
                                "company phone"
                              ],
                              "type": "string"
                            },
                            "value": {
                              "anyOf": [
                                {
                                  "description": "The contact's phone number.",
                                  "examples": [
                                    "+12345678901"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            }
                          },
                          "required": [
                            "name",
                            "value"
                          ]
                        }
                      },
                      "role": {
                        "anyOf": [
                          {
                            "description": "The contact's role.",
                            "examples": [
                              "Sales"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      }
                    },
                    "required": [
                      "firstName"
                    ]
                  },
                  "customFields": {
                    "type": "array",
                    "items": {
                      "allOf": [
                        {
                          "type": "object",
                          "properties": {
                            "key": {
                              "description": "The identifying key for contact custom field.",
                              "examples": [
                                "inbound-lead"
                              ],
                              "type": "string"
                            }
                          }
                        },
                        {
                          "anyOf": [
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "array",
                                      "items": {
                                        "type": "string"
                                      }
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "string"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "boolean"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "format": "date-time",
                                      "type": "string"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "number"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  },
                  "createdByUserId": {
                    "description": "The unique identifier of the user who created the contact.",
                    "examples": [
                      "US123abc"
                    ],
                    "pattern": "^US(.*)$",
                    "type": "string"
                  },
                  "source": {
                    "description": "The contact's source. Defaults to `null` for contacts created in the UI. Defaults to `public-api` for contacts created via the public API. Cannot be one of the following reserved words: `openphone`, `device`, `csv`, `zapier`, `google-people`, `other` or start with one of the following reserved prefixes: `openphone`, `csv`.",
                    "examples": [
                      "public-api",
                      "custom-hubspot",
                      "google-calendar"
                    ],
                    "default": "public-api",
                    "minLength": 1,
                    "maxLength": 72,
                    "type": "string"
                  },
                  "sourceUrl": {
                    "description": "A link to the contact in the source system.",
                    "format": "uri",
                    "examples": [
                      "https://openphone.co/contacts/664d0db69fcac7cf2e6ec"
                    ],
                    "minLength": 1,
                    "maxLength": 200,
                    "type": "string"
                  },
                  "externalId": {
                    "anyOf": [
                      {
                        "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                        "examples": [
                          "664d0db69fcac7cf2e6ec"
                        ],
                        "minLength": 1,
                        "maxLength": 75,
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  }
                },
                "required": [
                  "defaultFields"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The unique identifier of the contact.",
                          "examples": [
                            "664d0db69fcac7cf2e6ec"
                          ],
                          "type": "string"
                        },
                        "externalId": {
                          "anyOf": [
                            {
                              "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                              "examples": [
                                "664d0db69fcac7cf2e6ec"
                              ],
                              "minLength": 1,
                              "maxLength": 75,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "source": {
                          "anyOf": [
                            {
                              "description": "Indicates how the contact was created or where it originated from.",
                              "examples": [
                                "public-api"
                              ],
                              "minLength": 1,
                              "maxLength": 75,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "sourceUrl": {
                          "anyOf": [
                            {
                              "description": "A link to the contact in the source system.",
                              "format": "uri",
                              "examples": [
                                "https://openphone.co/contacts/664d0db69fcac7cf2e6ec"
                              ],
                              "minLength": 1,
                              "maxLength": 200,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "defaultFields": {
                          "type": "object",
                          "properties": {
                            "company": {
                              "anyOf": [
                                {
                                  "description": "The contact's company name.",
                                  "examples": [
                                    "OpenPhone"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "emails": {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name for the contact's email address.",
                                    "examples": [
                                      "company email"
                                    ],
                                    "type": "string"
                                  },
                                  "value": {
                                    "anyOf": [
                                      {
                                        "description": "The contact's email address.",
                                        "examples": [
                                          "abc@example.com"
                                        ],
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "id": {
                                    "description": "The unique identifier for the contact email field.",
                                    "examples": [
                                      "acb123"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name",
                                  "value"
                                ]
                              }
                            },
                            "firstName": {
                              "anyOf": [
                                {
                                  "description": "The contact's first name.",
                                  "examples": [
                                    "John"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "lastName": {
                              "anyOf": [
                                {
                                  "description": "The contact's last name.",
                                  "examples": [
                                    "Doe"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "phoneNumbers": {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name of the contact's phone number.",
                                    "examples": [
                                      "company phone"
                                    ],
                                    "type": "string"
                                  },
                                  "value": {
                                    "anyOf": [
                                      {
                                        "description": "The contact's phone number.",
                                        "examples": [
                                          "+12345678901"
                                        ],
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "id": {
                                    "description": "The unique identifier of the contact phone number field.",
                                    "examples": [
                                      "acb123"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name",
                                  "value"
                                ]
                              }
                            },
                            "role": {
                              "anyOf": [
                                {
                                  "description": "The contact's role.",
                                  "examples": [
                                    "Sales"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            }
                          },
                          "required": [
                            "company",
                            "emails",
                            "firstName",
                            "lastName",
                            "phoneNumbers",
                            "role"
                          ]
                        },
                        "customFields": {
                          "type": "array",
                          "items": {
                            "allOf": [
                              {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name of the custom contact field. This name is set by users in the OpenPhone interface when the custom field is created.",
                                    "examples": [
                                      "Inbound Lead"
                                    ],
                                    "type": "string"
                                  },
                                  "key": {
                                    "description": "The identifying key for contact custom field.",
                                    "examples": [
                                      "inbound-lead"
                                    ],
                                    "type": "string"
                                  },
                                  "id": {
                                    "description": "The unique identifier for the contact custom field.",
                                    "examples": [
                                      "66d0d87d534de8fd1c433cec3"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name"
                                ]
                              },
                              {
                                "anyOf": [
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "multi-select"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "array",
                                            "items": {
                                              "type": "string"
                                            }
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "address",
                                          "string",
                                          "url"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "boolean"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "boolean"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "date"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "format": "date-time",
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "number"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "number"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  }
                                ]
                              }
                            ]
                          }
                        },
                        "createdAt": {
                          "description": "Timestamp of contact creation in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "Timestamp of last contact update in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "createdByUserId": {
                          "description": "The unique identifier of the user who created the contact.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        }
                      },
                      "required": [
                        "id",
                        "externalId",
                        "source",
                        "sourceUrl",
                        "defaultFields",
                        "customFields",
                        "createdAt",
                        "updatedAt",
                        "createdByUserId"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Custom Field Item",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "409": {
            "description": "Conflict",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800409",
                      "type": "string"
                    },
                    "status": {
                      "const": 409,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Conflict",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      },
      "get": {
        "tags": [
          "Contacts"
        ],
        "summary": "List contacts",
        "description": "Retrieve a paginated list of contacts associated with specific external IDs. You can optionally filter the results further by providing a list of sources. **Note**: The `externalIds` parameter is currently required to specify the contacts you want to retrieve.",
        "operationId": "listContacts_v1",
        "parameters": [
          {
            "in": "query",
            "name": "externalIds",
            "required": true,
            "schema": {
              "description": "A list of unique identifiers from an external system used to retrieve specific contacts. This parameter is required and ensures the result set is limited to the contacts associated with the provided `externalIds`. These IDs must match the ones supplied during contact creation via the \"Create Contacts\" endpoint. Use this parameter to cross-reference and fetch contacts linked to external systems.",
              "type": "array",
              "items": {
                "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                "examples": [
                  "664d0db69fcac7cf2e6ec"
                ],
                "minLength": 1,
                "maxLength": 75,
                "type": "string"
              }
            }
          },
          {
            "in": "query",
            "name": "sources",
            "required": false,
            "schema": {
              "type": "array",
              "items": {
                "description": "Indicates how the contact was created or where it originated from.",
                "examples": [
                  "public-api"
                ],
                "minLength": 1,
                "maxLength": 75,
                "type": "string"
              }
            }
          },
          {
            "in": "query",
            "name": "maxResults",
            "required": true,
            "schema": {
              "description": "Maximum number of results to return per page.",
              "default": 10,
              "maximum": 50,
              "minimum": 1,
              "type": "integer"
            }
          },
          {
            "in": "query",
            "name": "pageToken",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": {
                            "description": "The unique identifier of the contact.",
                            "examples": [
                              "664d0db69fcac7cf2e6ec"
                            ],
                            "type": "string"
                          },
                          "externalId": {
                            "anyOf": [
                              {
                                "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                                "examples": [
                                  "664d0db69fcac7cf2e6ec"
                                ],
                                "minLength": 1,
                                "maxLength": 75,
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "source": {
                            "anyOf": [
                              {
                                "description": "Indicates how the contact was created or where it originated from.",
                                "examples": [
                                  "public-api"
                                ],
                                "minLength": 1,
                                "maxLength": 75,
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "sourceUrl": {
                            "anyOf": [
                              {
                                "description": "A link to the contact in the source system.",
                                "format": "uri",
                                "examples": [
                                  "https://openphone.co/contacts/664d0db69fcac7cf2e6ec"
                                ],
                                "minLength": 1,
                                "maxLength": 200,
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "defaultFields": {
                            "type": "object",
                            "properties": {
                              "company": {
                                "anyOf": [
                                  {
                                    "description": "The contact's company name.",
                                    "examples": [
                                      "OpenPhone"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "emails": {
                                "type": "array",
                                "items": {
                                  "type": "object",
                                  "properties": {
                                    "name": {
                                      "description": "The name for the contact's email address.",
                                      "examples": [
                                        "company email"
                                      ],
                                      "type": "string"
                                    },
                                    "value": {
                                      "anyOf": [
                                        {
                                          "description": "The contact's email address.",
                                          "examples": [
                                            "abc@example.com"
                                          ],
                                          "type": "string"
                                        },
                                        {
                                          "type": "null"
                                        }
                                      ]
                                    },
                                    "id": {
                                      "description": "The unique identifier for the contact email field.",
                                      "examples": [
                                        "acb123"
                                      ],
                                      "type": "string"
                                    }
                                  },
                                  "required": [
                                    "name",
                                    "value"
                                  ]
                                }
                              },
                              "firstName": {
                                "anyOf": [
                                  {
                                    "description": "The contact's first name.",
                                    "examples": [
                                      "John"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "lastName": {
                                "anyOf": [
                                  {
                                    "description": "The contact's last name.",
                                    "examples": [
                                      "Doe"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "phoneNumbers": {
                                "type": "array",
                                "items": {
                                  "type": "object",
                                  "properties": {
                                    "name": {
                                      "description": "The name of the contact's phone number.",
                                      "examples": [
                                        "company phone"
                                      ],
                                      "type": "string"
                                    },
                                    "value": {
                                      "anyOf": [
                                        {
                                          "description": "The contact's phone number.",
                                          "examples": [
                                            "+12345678901"
                                          ],
                                          "type": "string"
                                        },
                                        {
                                          "type": "null"
                                        }
                                      ]
                                    },
                                    "id": {
                                      "description": "The unique identifier of the contact phone number field.",
                                      "examples": [
                                        "acb123"
                                      ],
                                      "type": "string"
                                    }
                                  },
                                  "required": [
                                    "name",
                                    "value"
                                  ]
                                }
                              },
                              "role": {
                                "anyOf": [
                                  {
                                    "description": "The contact's role.",
                                    "examples": [
                                      "Sales"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              }
                            },
                            "required": [
                              "company",
                              "emails",
                              "firstName",
                              "lastName",
                              "phoneNumbers",
                              "role"
                            ]
                          },
                          "customFields": {
                            "type": "array",
                            "items": {
                              "allOf": [
                                {
                                  "type": "object",
                                  "properties": {
                                    "name": {
                                      "description": "The name of the custom contact field. This name is set by users in the OpenPhone interface when the custom field is created.",
                                      "examples": [
                                        "Inbound Lead"
                                      ],
                                      "type": "string"
                                    },
                                    "key": {
                                      "description": "The identifying key for contact custom field.",
                                      "examples": [
                                        "inbound-lead"
                                      ],
                                      "type": "string"
                                    },
                                    "id": {
                                      "description": "The unique identifier for the contact custom field.",
                                      "examples": [
                                        "66d0d87d534de8fd1c433cec3"
                                      ],
                                      "type": "string"
                                    }
                                  },
                                  "required": [
                                    "name"
                                  ]
                                },
                                {
                                  "anyOf": [
                                    {
                                      "type": "object",
                                      "properties": {
                                        "type": {
                                          "type": "string",
                                          "enum": [
                                            "multi-select"
                                          ]
                                        },
                                        "value": {
                                          "anyOf": [
                                            {
                                              "type": "array",
                                              "items": {
                                                "type": "string"
                                              }
                                            },
                                            {
                                              "type": "null"
                                            }
                                          ]
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "value"
                                      ]
                                    },
                                    {
                                      "type": "object",
                                      "properties": {
                                        "type": {
                                          "type": "string",
                                          "enum": [
                                            "address",
                                            "string",
                                            "url"
                                          ]
                                        },
                                        "value": {
                                          "anyOf": [
                                            {
                                              "type": "string"
                                            },
                                            {
                                              "type": "null"
                                            }
                                          ]
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "value"
                                      ]
                                    },
                                    {
                                      "type": "object",
                                      "properties": {
                                        "type": {
                                          "type": "string",
                                          "enum": [
                                            "boolean"
                                          ]
                                        },
                                        "value": {
                                          "anyOf": [
                                            {
                                              "type": "boolean"
                                            },
                                            {
                                              "type": "null"
                                            }
                                          ]
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "value"
                                      ]
                                    },
                                    {
                                      "type": "object",
                                      "properties": {
                                        "type": {
                                          "type": "string",
                                          "enum": [
                                            "date"
                                          ]
                                        },
                                        "value": {
                                          "anyOf": [
                                            {
                                              "format": "date-time",
                                              "type": "string"
                                            },
                                            {
                                              "type": "null"
                                            }
                                          ]
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "value"
                                      ]
                                    },
                                    {
                                      "type": "object",
                                      "properties": {
                                        "type": {
                                          "type": "string",
                                          "enum": [
                                            "number"
                                          ]
                                        },
                                        "value": {
                                          "anyOf": [
                                            {
                                              "type": "number"
                                            },
                                            {
                                              "type": "null"
                                            }
                                          ]
                                        }
                                      },
                                      "required": [
                                        "type",
                                        "value"
                                      ]
                                    }
                                  ]
                                }
                              ]
                            }
                          },
                          "createdAt": {
                            "description": "Timestamp of contact creation in ISO 8601 format.",
                            "examples": [
                              "2022-01-01T00:00:00Z"
                            ],
                            "format": "date-time",
                            "type": "string"
                          },
                          "updatedAt": {
                            "description": "Timestamp of last contact update in ISO 8601 format.",
                            "examples": [
                              "2022-01-01T00:00:00Z"
                            ],
                            "format": "date-time",
                            "type": "string"
                          },
                          "createdByUserId": {
                            "description": "The unique identifier of the user who created the contact.",
                            "examples": [
                              "US123abc"
                            ],
                            "pattern": "^US(.*)$",
                            "type": "string"
                          }
                        },
                        "required": [
                          "id",
                          "externalId",
                          "source",
                          "sourceUrl",
                          "defaultFields",
                          "customFields",
                          "createdAt",
                          "updatedAt",
                          "createdByUserId"
                        ]
                      }
                    },
                    "totalItems": {
                      "description": "Total number of items available. ⚠️ Note: `totalItems` is not accurately returning the total number of items that can be paginated. We are working on fixing this issue.",
                      "type": "integer"
                    },
                    "nextPageToken": {
                      "anyOf": [
                        {
                          "type": "string"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    }
                  },
                  "required": [
                    "data",
                    "totalItems",
                    "nextPageToken"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Custom Field Item",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "409": {
            "description": "Conflict",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800409",
                      "type": "string"
                    },
                    "status": {
                      "const": 409,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Conflict",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/contacts/{id}": {
      "get": {
        "tags": [
          "Contacts"
        ],
        "summary": "Get a contact by ID",
        "description": "Retrieve detailed information about a specific contact in your OpenPhone workspace using the contact's unique identifier.",
        "operationId": "getContactById_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "The unique identifier of the contact.",
              "examples": [
                "66d0d87e8dc1211467372303"
              ],
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The unique identifier of the contact.",
                          "examples": [
                            "664d0db69fcac7cf2e6ec"
                          ],
                          "type": "string"
                        },
                        "externalId": {
                          "anyOf": [
                            {
                              "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                              "examples": [
                                "664d0db69fcac7cf2e6ec"
                              ],
                              "minLength": 1,
                              "maxLength": 75,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "source": {
                          "anyOf": [
                            {
                              "description": "Indicates how the contact was created or where it originated from.",
                              "examples": [
                                "public-api"
                              ],
                              "minLength": 1,
                              "maxLength": 75,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "sourceUrl": {
                          "anyOf": [
                            {
                              "description": "A link to the contact in the source system.",
                              "format": "uri",
                              "examples": [
                                "https://openphone.co/contacts/664d0db69fcac7cf2e6ec"
                              ],
                              "minLength": 1,
                              "maxLength": 200,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "defaultFields": {
                          "type": "object",
                          "properties": {
                            "company": {
                              "anyOf": [
                                {
                                  "description": "The contact's company name.",
                                  "examples": [
                                    "OpenPhone"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "emails": {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name for the contact's email address.",
                                    "examples": [
                                      "company email"
                                    ],
                                    "type": "string"
                                  },
                                  "value": {
                                    "anyOf": [
                                      {
                                        "description": "The contact's email address.",
                                        "examples": [
                                          "abc@example.com"
                                        ],
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "id": {
                                    "description": "The unique identifier for the contact email field.",
                                    "examples": [
                                      "acb123"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name",
                                  "value"
                                ]
                              }
                            },
                            "firstName": {
                              "anyOf": [
                                {
                                  "description": "The contact's first name.",
                                  "examples": [
                                    "John"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "lastName": {
                              "anyOf": [
                                {
                                  "description": "The contact's last name.",
                                  "examples": [
                                    "Doe"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "phoneNumbers": {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name of the contact's phone number.",
                                    "examples": [
                                      "company phone"
                                    ],
                                    "type": "string"
                                  },
                                  "value": {
                                    "anyOf": [
                                      {
                                        "description": "The contact's phone number.",
                                        "examples": [
                                          "+12345678901"
                                        ],
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "id": {
                                    "description": "The unique identifier of the contact phone number field.",
                                    "examples": [
                                      "acb123"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name",
                                  "value"
                                ]
                              }
                            },
                            "role": {
                              "anyOf": [
                                {
                                  "description": "The contact's role.",
                                  "examples": [
                                    "Sales"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            }
                          },
                          "required": [
                            "company",
                            "emails",
                            "firstName",
                            "lastName",
                            "phoneNumbers",
                            "role"
                          ]
                        },
                        "customFields": {
                          "type": "array",
                          "items": {
                            "allOf": [
                              {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name of the custom contact field. This name is set by users in the OpenPhone interface when the custom field is created.",
                                    "examples": [
                                      "Inbound Lead"
                                    ],
                                    "type": "string"
                                  },
                                  "key": {
                                    "description": "The identifying key for contact custom field.",
                                    "examples": [
                                      "inbound-lead"
                                    ],
                                    "type": "string"
                                  },
                                  "id": {
                                    "description": "The unique identifier for the contact custom field.",
                                    "examples": [
                                      "66d0d87d534de8fd1c433cec3"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name"
                                ]
                              },
                              {
                                "anyOf": [
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "multi-select"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "array",
                                            "items": {
                                              "type": "string"
                                            }
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "address",
                                          "string",
                                          "url"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "boolean"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "boolean"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "date"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "format": "date-time",
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "number"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "number"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  }
                                ]
                              }
                            ]
                          }
                        },
                        "createdAt": {
                          "description": "Timestamp of contact creation in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "Timestamp of last contact update in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "createdByUserId": {
                          "description": "The unique identifier of the user who created the contact.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        }
                      },
                      "required": [
                        "id",
                        "externalId",
                        "source",
                        "sourceUrl",
                        "defaultFields",
                        "customFields",
                        "createdAt",
                        "updatedAt",
                        "createdByUserId"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Custom Field Item",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "409": {
            "description": "Conflict",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800409",
                      "type": "string"
                    },
                    "status": {
                      "const": 409,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Conflict",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      },
      "patch": {
        "tags": [
          "Contacts"
        ],
        "summary": "Update a contact by ID",
        "description": "Modify an existing contact in your OpenPhone workspace using the contact's unique identifier.",
        "operationId": "updateContactById_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "The unique identifier of the contact.",
              "examples": [
                "66d0d87e8dc1211467372303"
              ],
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "externalId": {
                    "anyOf": [
                      {
                        "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                        "examples": [
                          "664d0db69fcac7cf2e6ec"
                        ],
                        "minLength": 1,
                        "maxLength": 75,
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "source": {
                    "anyOf": [
                      {
                        "description": "Indicates how the contact was created or where it originated from.",
                        "examples": [
                          "public-api"
                        ],
                        "minLength": 1,
                        "maxLength": 75,
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "sourceUrl": {
                    "anyOf": [
                      {
                        "description": "A link to the contact in the source system.",
                        "format": "uri",
                        "examples": [
                          "https://openphone.co/contacts/664d0db69fcac7cf2e6ec"
                        ],
                        "minLength": 1,
                        "maxLength": 200,
                        "type": "string"
                      },
                      {
                        "type": "null"
                      }
                    ]
                  },
                  "defaultFields": {
                    "type": "object",
                    "properties": {
                      "company": {
                        "anyOf": [
                          {
                            "description": "The contact's company name.",
                            "examples": [
                              "OpenPhone"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "emails": {
                        "type": "array",
                        "items": {
                          "type": "object",
                          "properties": {
                            "name": {
                              "description": "The name for the contact's email address.",
                              "examples": [
                                "company email"
                              ],
                              "type": "string"
                            },
                            "value": {
                              "anyOf": [
                                {
                                  "description": "The contact's email address. If set to null during a patch operation, it will remove the email item from the contact.",
                                  "examples": [
                                    "info@openphone.com"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "id": {
                              "description": "The unique identifier for the contact email field.",
                              "examples": [
                                "acb123"
                              ],
                              "type": "string"
                            }
                          },
                          "required": [
                            "name",
                            "value"
                          ]
                        }
                      },
                      "firstName": {
                        "anyOf": [
                          {
                            "description": "The contact's first name.",
                            "examples": [
                              "John"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "lastName": {
                        "anyOf": [
                          {
                            "description": "The contact's last name.",
                            "examples": [
                              "Doe"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "phoneNumbers": {
                        "type": "array",
                        "items": {
                          "type": "object",
                          "properties": {
                            "name": {
                              "description": "The name of the contact's phone number.",
                              "examples": [
                                "company phone"
                              ],
                              "type": "string"
                            },
                            "value": {
                              "anyOf": [
                                {
                                  "description": "The contact's phone number. If set to null during a patch operation, it will remove the phone number item from the contact.",
                                  "examples": [
                                    "+15555555555"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "id": {
                              "description": "The unique identifier of the contact phone number field.",
                              "examples": [
                                "acb123"
                              ],
                              "type": "string"
                            }
                          },
                          "required": [
                            "name",
                            "value"
                          ]
                        }
                      },
                      "role": {
                        "anyOf": [
                          {
                            "description": "The contact's role.",
                            "examples": [
                              "Sales"
                            ],
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      }
                    }
                  },
                  "customFields": {
                    "type": "array",
                    "items": {
                      "allOf": [
                        {
                          "type": "object",
                          "properties": {
                            "key": {
                              "description": "The identifying key for contact custom field.",
                              "examples": [
                                "inbound-lead"
                              ],
                              "type": "string"
                            },
                            "id": {
                              "description": "The unique identifier for the contact custom field.",
                              "examples": [
                                "66d0d87d534de8fd1c433cec3"
                              ],
                              "type": "string"
                            }
                          }
                        },
                        {
                          "anyOf": [
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "array",
                                      "items": {
                                        "type": "string"
                                      }
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "string"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "boolean"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "format": "date-time",
                                      "type": "string"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            },
                            {
                              "type": "object",
                              "properties": {
                                "value": {
                                  "anyOf": [
                                    {
                                      "type": "number"
                                    },
                                    {
                                      "type": "null"
                                    }
                                  ]
                                }
                              },
                              "required": [
                                "value"
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The unique identifier of the contact.",
                          "examples": [
                            "664d0db69fcac7cf2e6ec"
                          ],
                          "type": "string"
                        },
                        "externalId": {
                          "anyOf": [
                            {
                              "description": "A unique identifier from an external system that can optionally be supplied when creating a contact. This ID is used to associate the contact with records in other systems and is required for retrieving the contact later via the \"List Contacts\" endpoint. Ensure the `externalId` is unique and consistent across systems for accurate cross-referencing.",
                              "examples": [
                                "664d0db69fcac7cf2e6ec"
                              ],
                              "minLength": 1,
                              "maxLength": 75,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "source": {
                          "anyOf": [
                            {
                              "description": "Indicates how the contact was created or where it originated from.",
                              "examples": [
                                "public-api"
                              ],
                              "minLength": 1,
                              "maxLength": 75,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "sourceUrl": {
                          "anyOf": [
                            {
                              "description": "A link to the contact in the source system.",
                              "format": "uri",
                              "examples": [
                                "https://openphone.co/contacts/664d0db69fcac7cf2e6ec"
                              ],
                              "minLength": 1,
                              "maxLength": 200,
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "defaultFields": {
                          "type": "object",
                          "properties": {
                            "company": {
                              "anyOf": [
                                {
                                  "description": "The contact's company name.",
                                  "examples": [
                                    "OpenPhone"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "emails": {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name for the contact's email address.",
                                    "examples": [
                                      "company email"
                                    ],
                                    "type": "string"
                                  },
                                  "value": {
                                    "anyOf": [
                                      {
                                        "description": "The contact's email address.",
                                        "examples": [
                                          "abc@example.com"
                                        ],
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "id": {
                                    "description": "The unique identifier for the contact email field.",
                                    "examples": [
                                      "acb123"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name",
                                  "value"
                                ]
                              }
                            },
                            "firstName": {
                              "anyOf": [
                                {
                                  "description": "The contact's first name.",
                                  "examples": [
                                    "John"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "lastName": {
                              "anyOf": [
                                {
                                  "description": "The contact's last name.",
                                  "examples": [
                                    "Doe"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "phoneNumbers": {
                              "type": "array",
                              "items": {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name of the contact's phone number.",
                                    "examples": [
                                      "company phone"
                                    ],
                                    "type": "string"
                                  },
                                  "value": {
                                    "anyOf": [
                                      {
                                        "description": "The contact's phone number.",
                                        "examples": [
                                          "+12345678901"
                                        ],
                                        "type": "string"
                                      },
                                      {
                                        "type": "null"
                                      }
                                    ]
                                  },
                                  "id": {
                                    "description": "The unique identifier of the contact phone number field.",
                                    "examples": [
                                      "acb123"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name",
                                  "value"
                                ]
                              }
                            },
                            "role": {
                              "anyOf": [
                                {
                                  "description": "The contact's role.",
                                  "examples": [
                                    "Sales"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            }
                          },
                          "required": [
                            "company",
                            "emails",
                            "firstName",
                            "lastName",
                            "phoneNumbers",
                            "role"
                          ]
                        },
                        "customFields": {
                          "type": "array",
                          "items": {
                            "allOf": [
                              {
                                "type": "object",
                                "properties": {
                                  "name": {
                                    "description": "The name of the custom contact field. This name is set by users in the OpenPhone interface when the custom field is created.",
                                    "examples": [
                                      "Inbound Lead"
                                    ],
                                    "type": "string"
                                  },
                                  "key": {
                                    "description": "The identifying key for contact custom field.",
                                    "examples": [
                                      "inbound-lead"
                                    ],
                                    "type": "string"
                                  }
                                },
                                "required": [
                                  "name"
                                ]
                              },
                              {
                                "anyOf": [
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "multi-select"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "array",
                                            "items": {
                                              "type": "string"
                                            }
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "address",
                                          "string",
                                          "url"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "boolean"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "boolean"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "date"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "format": "date-time",
                                            "type": "string"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  },
                                  {
                                    "type": "object",
                                    "properties": {
                                      "type": {
                                        "type": "string",
                                        "enum": [
                                          "number"
                                        ]
                                      },
                                      "value": {
                                        "anyOf": [
                                          {
                                            "type": "number"
                                          },
                                          {
                                            "type": "null"
                                          }
                                        ]
                                      }
                                    },
                                    "required": [
                                      "type",
                                      "value"
                                    ]
                                  }
                                ]
                              }
                            ]
                          }
                        },
                        "createdAt": {
                          "description": "Timestamp of contact creation in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "Timestamp of last contact update in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "createdByUserId": {
                          "description": "The unique identifier of the user who created the contact.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        }
                      },
                      "required": [
                        "id",
                        "externalId",
                        "source",
                        "sourceUrl",
                        "defaultFields",
                        "customFields",
                        "createdAt",
                        "updatedAt",
                        "createdByUserId"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Custom Field Item",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "409": {
            "description": "Conflict",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800409",
                      "type": "string"
                    },
                    "status": {
                      "const": 409,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Conflict",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Contacts"
        ],
        "summary": "Delete a contact",
        "description": "Delete a contact by its unique identifier.",
        "operationId": "deleteContact_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "The unique identifier of the contact.",
              "examples": [
                "66d0d87e8dc1211467372303"
              ],
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "204": {
            "description": "Success"
          },
          "400": {
            "description": "Invalid Custom Field Item",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Custom Field Item",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "409": {
            "description": "Conflict",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0800409",
                      "type": "string"
                    },
                    "status": {
                      "const": 409,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Conflict",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0801500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/conversations": {
      "get": {
        "tags": [
          "Conversations"
        ],
        "summary": "List Conversations",
        "description": "Fetch a paginated list of conversations of OpenPhone conversations. Can be filtered by user and/or phone numbers. Defaults to all conversations in the OpenPhone organization. Results are returned in descending order based on the most recent conversation.",
        "operationId": "listConversations_v1",
        "parameters": [
          {
            "in": "query",
            "name": "phoneNumber",
            "required": false,
            "schema": {
              "description": "DEPRECATED, use `phoneNumbers` instead. If both `phoneNumber` and `phoneNumbers` are provided, `phoneNumbers` will be used. Filters results to only include conversations with the specified OpenPhone phone number. Can be either your OpenPhone phone number ID or the full phone number in E.164 format.",
              "examples": [
                "+15555555555",
                "PN123abc"
              ],
              "deprecated": true,
              "anyOf": [
                {
                  "pattern": "^\\+[1-9]\\d{1,14}$",
                  "description": "A phone number in E.164 format, including the country code.",
                  "examples": [
                    "+15555555555"
                  ],
                  "type": "string"
                },
                {
                  "pattern": "^PN(.*)$",
                  "type": "string"
                }
              ]
            }
          },
          {
            "in": "query",
            "name": "phoneNumbers",
            "required": false,
            "schema": {
              "description": "Filters results to only include conversations with the specified OpenPhone phone numbers. Each item can be either an OpenPhone phone number ID or a full phone number in E.164 format.",
              "examples": [
                [
                  "+15555555555",
                  "PN123abc"
                ]
              ],
              "minItems": 1,
              "maxItems": 100,
              "type": "array",
              "items": {
                "anyOf": [
                  {
                    "pattern": "^\\+[1-9]\\d{1,14}$",
                    "description": "A phone number in E.164 format, including the country code.",
                    "examples": [
                      "+15555555555"
                    ],
                    "type": "string"
                  },
                  {
                    "pattern": "^PN(.*)$",
                    "type": "string"
                  }
                ]
              }
            }
          },
          {
            "in": "query",
            "name": "userId",
            "required": false,
            "schema": {
              "description": "The unique identifier of the user the making the request. Used to filter results to only include the user's conversations.",
              "examples": [
                "US123abc"
              ],
              "pattern": "^US(.*)$",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "createdAfter",
            "required": false,
            "schema": {
              "description": "Filter results to only include conversations created after the specified date and time, in ISO_8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "createdBefore",
            "required": false,
            "schema": {
              "description": "Filter results to only include conversations created before the specified date and time, in ISO_8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "excludeInactive",
            "required": false,
            "schema": {
              "description": "Exclude inactive conversations from the results.",
              "examples": [
                true
              ],
              "type": "boolean"
            }
          },
          {
            "in": "query",
            "name": "updatedAfter",
            "required": false,
            "schema": {
              "description": "Filter results to only include conversations updated after the specified date and time, in ISO_8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "updatedBefore",
            "required": false,
            "schema": {
              "description": "Filter results to only include conversations updated before the specified date and time, in ISO_8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "maxResults",
            "required": true,
            "schema": {
              "description": "Maximum number of results to return per page.",
              "default": 10,
              "maximum": 100,
              "minimum": 1,
              "type": "integer"
            }
          },
          {
            "in": "query",
            "name": "pageToken",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "assignedTo": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "createdAt": {
                            "anyOf": [
                              {
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "deletedAt": {
                            "anyOf": [
                              {
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "id": {
                            "pattern": "^CN(.*)$",
                            "type": "string"
                          },
                          "lastActivityAt": {
                            "anyOf": [
                              {
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "lastActivityId": {
                            "anyOf": [
                              {
                                "pattern": "^AC(.*)$",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "mutedUntil": {
                            "anyOf": [
                              {
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "name": {
                            "anyOf": [
                              {
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "participants": {
                            "type": "array",
                            "items": {
                              "pattern": "^\\+[1-9]\\d{1,14}$",
                              "description": "A phone number in E.164 format, including the country code.",
                              "examples": [
                                "+15555555555"
                              ],
                              "type": "string"
                            }
                          },
                          "phoneNumberId": {
                            "pattern": "^PN(.*)$",
                            "type": "string"
                          },
                          "snoozedUntil": {
                            "anyOf": [
                              {
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "updatedAt": {
                            "anyOf": [
                              {
                                "format": "date-time",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          }
                        },
                        "required": [
                          "assignedTo",
                          "createdAt",
                          "deletedAt",
                          "id",
                          "lastActivityAt",
                          "lastActivityId",
                          "mutedUntil",
                          "name",
                          "participants",
                          "phoneNumberId",
                          "snoozedUntil",
                          "updatedAt"
                        ]
                      }
                    },
                    "totalItems": {
                      "description": "Total number of items available. ⚠️ Note: `totalItems` is not accurately returning the total number of items that can be paginated. We are working on fixing this issue.",
                      "type": "integer"
                    },
                    "nextPageToken": {
                      "anyOf": [
                        {
                          "type": "string"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    }
                  },
                  "required": [
                    "data",
                    "totalItems",
                    "nextPageToken"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "1000400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "1000401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "1001403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "1000404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "1001500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/messages": {
      "post": {
        "tags": [
          "Messages"
        ],
        "summary": "Send a text message",
        "description": "Send a text message from your OpenPhone number to a recipient.",
        "operationId": "sendMessage_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "content": {
                    "minLength": 1,
                    "maxLength": 1600,
                    "pattern": ".*\\S.*",
                    "description": "The text content of the message to be sent.",
                    "type": "string"
                  },
                  "phoneNumberId": {
                    "description": "DEPRECATED, use \"from\" instead. OpenPhone phone number ID to send a message from",
                    "examples": [
                      "OP1232abc"
                    ],
                    "deprecated": true,
                    "pattern": "^PN(.*)$",
                    "type": "string"
                  },
                  "from": {
                    "anyOf": [
                      {
                        "pattern": "^PN(.*)$",
                        "type": "string"
                      },
                      {
                        "pattern": "^\\+[1-9]\\d{1,14}$",
                        "description": "A phone number in E.164 format, including the country code.",
                        "examples": [
                          "+15555555555"
                        ],
                        "type": "string"
                      }
                    ]
                  },
                  "to": {
                    "minItems": 1,
                    "maxItems": 1,
                    "type": "array",
                    "items": {
                      "pattern": "^\\+[1-9]\\d{1,14}$",
                      "description": "A phone number in E.164 format, including the country code.",
                      "examples": [
                        "+15555555555"
                      ],
                      "type": "string"
                    }
                  },
                  "userId": {
                    "description": "The unique identifier of the OpenPhone user sending the message. If not provided, defaults to the phone number owner.",
                    "examples": [
                      "US123abc"
                    ],
                    "pattern": "^US(.*)$",
                    "type": "string"
                  },
                  "setInboxStatus": {
                    "type": "string",
                    "enum": [
                      "done"
                    ],
                    "description": "Used to set the status of the related OpenPhone inbox conversation. The default behavior without setting this parameter will be for the message sent to show up as an open conversation in the user's inbox. Setting the parameter to `'done'` would move the conversation to the Done inbox view.",
                    "examples": [
                      "done"
                    ]
                  }
                },
                "required": [
                  "content",
                  "from",
                  "to"
                ]
              }
            }
          }
        },
        "responses": {
          "202": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The unique identifier of the message.",
                          "examples": [
                            "AC123abc"
                          ],
                          "pattern": "^AC(.*)$",
                          "type": "string"
                        },
                        "to": {
                          "type": "array",
                          "items": {
                            "pattern": "^\\+[1-9]\\d{1,14}$",
                            "description": "A phone number in E.164 format, including the country code.",
                            "examples": [
                              "+15555555555"
                            ],
                            "type": "string"
                          }
                        },
                        "from": {
                          "pattern": "^\\+[1-9]\\d{1,14}$",
                          "description": "A phone number in E.164 format, including the country code.",
                          "examples": [
                            "+15555555555"
                          ],
                          "type": "string"
                        },
                        "text": {
                          "description": "The content of the message.",
                          "examples": [
                            "Hello, world!"
                          ],
                          "type": "string"
                        },
                        "phoneNumberId": {
                          "anyOf": [
                            {
                              "description": "The unique identifier of the OpenPhone phone number that the message was sent from.",
                              "examples": [
                                "PN123abc"
                              ],
                              "pattern": "^PN(.*)$",
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "direction": {
                          "type": "string",
                          "enum": [
                            "incoming",
                            "outgoing"
                          ],
                          "description": "The direction of the message relative to the OpenPhone number.",
                          "examples": [
                            "incoming"
                          ]
                        },
                        "userId": {
                          "description": "The unique identifier of the user who sent the message. Null for incoming messages.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "queued",
                            "sent",
                            "delivered",
                            "undelivered"
                          ],
                          "description": "The status of the message.",
                          "examples": [
                            "sent"
                          ]
                        },
                        "createdAt": {
                          "description": "The timestamp when the message was created at, in ISO 8601 format",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "The timestamp when the message status was last updated, in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        }
                      },
                      "required": [
                        "id",
                        "to",
                        "from",
                        "text",
                        "phoneNumberId",
                        "direction",
                        "userId",
                        "status",
                        "createdAt",
                        "updatedAt"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "A2P Registration Not Approved",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0206400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "A2P Registration Not Approved",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "A2P Registration Not Approved",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "402": {
            "description": "Not Enough Credits",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200402",
                      "type": "string"
                    },
                    "status": {
                      "const": 402,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Enough Credits",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "The organization does not have enough prepaid credits to send the message",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0202403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0201500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      },
      "get": {
        "tags": [
          "Messages"
        ],
        "summary": "List messages",
        "description": "Retrieve a chronological list of messages exchanged between your OpenPhone number and specified participants, with support for filtering and pagination. ",
        "operationId": "listMessages_v1",
        "parameters": [
          {
            "in": "query",
            "name": "phoneNumberId",
            "required": true,
            "schema": {
              "description": "The unique identifier of the OpenPhone number used to send or receive the messages. PhoneNumberID can be retrieved via the Get Phone Numbers endpoint.",
              "examples": [
                "OP123abc"
              ],
              "pattern": "^PN(.*)$",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "userId",
            "required": false,
            "schema": {
              "description": "The unique identifier of the user the message was sent from.",
              "examples": [
                "US123abc"
              ],
              "pattern": "^US(.*)$",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "participants",
            "required": true,
            "schema": {
              "description": "Array of phone numbers involved in the conversation, excluding your OpenPhone number, in E.164 format.",
              "examples": [
                "+15555555555"
              ],
              "type": "array",
              "items": {
                "pattern": "^\\+[1-9]\\d{1,14}$",
                "description": "A phone number in E.164 format, including the country code.",
                "examples": [
                  "+15555555555"
                ],
                "type": "string"
              }
            }
          },
          {
            "in": "query",
            "name": "since",
            "required": false,
            "schema": {
              "deprecated": true,
              "description": "DEPRECATED, use \"createdAfter\" or \"createdBefore\" instead. \"since\" currently behaves as \"createdBefore\" and will be removed in an upcoming release.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "createdAfter",
            "required": false,
            "schema": {
              "description": "Filter results to only include messages created after the specified date and time, in ISO_8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "createdBefore",
            "required": false,
            "schema": {
              "description": "Filter results to only include messages created before the specified date and time, in ISO_8601 format.",
              "examples": [
                "2022-01-01T00:00:00Z"
              ],
              "format": "date-time",
              "type": "string"
            }
          },
          {
            "in": "query",
            "name": "maxResults",
            "required": true,
            "schema": {
              "description": "Maximum number of results to return per page.",
              "default": 10,
              "maximum": 100,
              "minimum": 1,
              "type": "integer"
            }
          },
          {
            "in": "query",
            "name": "pageToken",
            "required": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "id": {
                            "description": "The unique identifier of the message.",
                            "examples": [
                              "AC123abc"
                            ],
                            "pattern": "^AC(.*)$",
                            "type": "string"
                          },
                          "to": {
                            "type": "array",
                            "items": {
                              "pattern": "^\\+[1-9]\\d{1,14}$",
                              "description": "A phone number in E.164 format, including the country code.",
                              "examples": [
                                "+15555555555"
                              ],
                              "type": "string"
                            }
                          },
                          "from": {
                            "pattern": "^\\+[1-9]\\d{1,14}$",
                            "description": "A phone number in E.164 format, including the country code.",
                            "examples": [
                              "+15555555555"
                            ],
                            "type": "string"
                          },
                          "text": {
                            "description": "The content of the message.",
                            "examples": [
                              "Hello, world!"
                            ],
                            "type": "string"
                          },
                          "phoneNumberId": {
                            "anyOf": [
                              {
                                "description": "The unique identifier of the OpenPhone phone number that the message was sent from.",
                                "examples": [
                                  "PN123abc"
                                ],
                                "pattern": "^PN(.*)$",
                                "type": "string"
                              },
                              {
                                "type": "null"
                              }
                            ]
                          },
                          "direction": {
                            "type": "string",
                            "enum": [
                              "incoming",
                              "outgoing"
                            ],
                            "description": "The direction of the message relative to the OpenPhone number.",
                            "examples": [
                              "incoming"
                            ]
                          },
                          "userId": {
                            "description": "The unique identifier of the user who sent the message. Null for incoming messages.",
                            "examples": [
                              "US123abc"
                            ],
                            "pattern": "^US(.*)$",
                            "type": "string"
                          },
                          "status": {
                            "type": "string",
                            "enum": [
                              "queued",
                              "sent",
                              "delivered",
                              "undelivered"
                            ],
                            "description": "The status of the message.",
                            "examples": [
                              "sent"
                            ]
                          },
                          "createdAt": {
                            "description": "The timestamp when the message was created at, in ISO 8601 format",
                            "examples": [
                              "2022-01-01T00:00:00Z"
                            ],
                            "format": "date-time",
                            "type": "string"
                          },
                          "updatedAt": {
                            "description": "The timestamp when the message status was last updated, in ISO 8601 format.",
                            "examples": [
                              "2022-01-01T00:00:00Z"
                            ],
                            "format": "date-time",
                            "type": "string"
                          }
                        },
                        "required": [
                          "id",
                          "to",
                          "from",
                          "text",
                          "phoneNumberId",
                          "direction",
                          "userId",
                          "status",
                          "createdAt",
                          "updatedAt"
                        ]
                      }
                    },
                    "totalItems": {
                      "description": "Total number of items available. ⚠️ Note: `totalItems` is not accurately returning the total number of items that can be paginated. We are working on fixing this issue.",
                      "type": "integer"
                    },
                    "nextPageToken": {
                      "anyOf": [
                        {
                          "type": "string"
                        },
                        {
                          "type": "null"
                        }
                      ]
                    }
                  },
                  "required": [
                    "data",
                    "totalItems",
                    "nextPageToken"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "A2P Registration Not Approved",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0206400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "A2P Registration Not Approved",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "A2P Registration Not Approved",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "402": {
            "description": "Not Enough Credits",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200402",
                      "type": "string"
                    },
                    "status": {
                      "const": 402,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Enough Credits",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "The organization does not have enough prepaid credits to send the message",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0202403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0201500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/messages/{id}": {
      "get": {
        "tags": [
          "Messages"
        ],
        "summary": "Get a message by ID",
        "description": "Get a message by its unique identifier.",
        "operationId": "getMessageById_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "The unique identifier of a message",
              "examples": [
                "AC123abc"
              ],
              "pattern": "^AC(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The unique identifier of the message.",
                          "examples": [
                            "AC123abc"
                          ],
                          "pattern": "^AC(.*)$",
                          "type": "string"
                        },
                        "to": {
                          "type": "array",
                          "items": {
                            "pattern": "^\\+[1-9]\\d{1,14}$",
                            "description": "A phone number in E.164 format, including the country code.",
                            "examples": [
                              "+15555555555"
                            ],
                            "type": "string"
                          }
                        },
                        "from": {
                          "pattern": "^\\+[1-9]\\d{1,14}$",
                          "description": "A phone number in E.164 format, including the country code.",
                          "examples": [
                            "+15555555555"
                          ],
                          "type": "string"
                        },
                        "text": {
                          "description": "The content of the message.",
                          "examples": [
                            "Hello, world!"
                          ],
                          "type": "string"
                        },
                        "phoneNumberId": {
                          "anyOf": [
                            {
                              "description": "The unique identifier of the OpenPhone phone number that the message was sent from.",
                              "examples": [
                                "PN123abc"
                              ],
                              "pattern": "^PN(.*)$",
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "direction": {
                          "type": "string",
                          "enum": [
                            "incoming",
                            "outgoing"
                          ],
                          "description": "The direction of the message relative to the OpenPhone number.",
                          "examples": [
                            "incoming"
                          ]
                        },
                        "userId": {
                          "description": "The unique identifier of the user who sent the message. Null for incoming messages.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "queued",
                            "sent",
                            "delivered",
                            "undelivered"
                          ],
                          "description": "The status of the message.",
                          "examples": [
                            "sent"
                          ]
                        },
                        "createdAt": {
                          "description": "The timestamp when the message was created at, in ISO 8601 format",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "The timestamp when the message status was last updated, in ISO 8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        }
                      },
                      "required": [
                        "id",
                        "to",
                        "from",
                        "text",
                        "phoneNumberId",
                        "direction",
                        "userId",
                        "status",
                        "createdAt",
                        "updatedAt"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "A2P Registration Not Approved",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0206400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "A2P Registration Not Approved",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "A2P Registration Not Approved",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "402": {
            "description": "Not Enough Credits",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200402",
                      "type": "string"
                    },
                    "status": {
                      "const": 402,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Enough Credits",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "The organization does not have enough prepaid credits to send the message",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Not Phone Number User",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0202403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Not Phone Number User",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0200404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0201500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/phone-numbers": {
      "get": {
        "tags": [
          "Phone Numbers"
        ],
        "summary": "List phone numbers",
        "description": "Retrieve the list of phone numbers and users associated with your OpenPhone workspace.",
        "operationId": "listPhoneNumbers_v1",
        "parameters": [
          {
            "in": "query",
            "name": "userId",
            "required": false,
            "schema": {
              "description": "Filter results to return only phone numbers associated with the specified user\"s unique identifier.",
              "examples": [
                "US123abc"
              ],
              "pattern": "^US(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ListPhoneNumbersResponse"
                }
              }
            }
          },
          "400": {
            "description": "Bad Request",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0400400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Bad Request",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0400401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0400403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0400404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0401500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/webhooks": {
      "get": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Lists all webhooks",
        "description": "List all webhooks for a user.",
        "operationId": "listWebhooks_v1",
        "parameters": [
          {
            "in": "query",
            "name": "userId",
            "required": false,
            "schema": {
              "description": "The unique identifier the user. Defaults to the workspace owner.",
              "examples": "U55wgP5I5",
              "pattern": "^US(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "array",
                      "items": {
                        "anyOf": [
                          {
                            "type": "object",
                            "properties": {
                              "id": {
                                "description": "The webhook's ID",
                                "examples": [
                                  "WHabcd1234"
                                ],
                                "pattern": "^WH(.*)$",
                                "type": "string"
                              },
                              "userId": {
                                "description": "The unique identifier of the user that created the webhook.",
                                "examples": [
                                  "US123abc"
                                ],
                                "pattern": "^US(.*)$",
                                "type": "string"
                              },
                              "orgId": {
                                "description": "The unique identifier of the organization the webhook belongs to",
                                "examples": [
                                  "OR1223abc"
                                ],
                                "pattern": "^OR(.*)$",
                                "type": "string"
                              },
                              "label": {
                                "anyOf": [
                                  {
                                    "description": "The webhook's label.",
                                    "examples": [
                                      "my webhook label"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "status": {
                                "type": "string",
                                "enum": [
                                  "enabled",
                                  "disabled"
                                ],
                                "default": "enabled",
                                "description": "The status of the webhook.",
                                "examples": [
                                  "enabled"
                                ]
                              },
                              "url": {
                                "format": "uri",
                                "description": "The endpoint that receives events from the webhook.",
                                "examples": [
                                  "https://example.com/"
                                ],
                                "type": "string"
                              },
                              "key": {
                                "description": "Webhook key",
                                "examples": [
                                  "example-key"
                                ],
                                "type": "string"
                              },
                              "createdAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "updatedAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "deletedAt": {
                                "anyOf": [
                                  {
                                    "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                    "examples": [
                                      "2022-01-01T00:00:00Z"
                                    ],
                                    "format": "date-time",
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "events": {
                                "type": "array",
                                "items": {
                                  "type": "string",
                                  "enum": [
                                    "message.received",
                                    "message.delivered"
                                  ]
                                }
                              },
                              "resourceIds": {
                                "anyOf": [
                                  {
                                    "type": "array",
                                    "items": {
                                      "pattern": "^PN(.*)$",
                                      "type": "string"
                                    }
                                  },
                                  {
                                    "type": "array",
                                    "items": {
                                      "const": "*",
                                      "type": "string"
                                    }
                                  }
                                ]
                              }
                            },
                            "required": [
                              "id",
                              "userId",
                              "orgId",
                              "label",
                              "status",
                              "url",
                              "key",
                              "createdAt",
                              "updatedAt",
                              "deletedAt",
                              "events",
                              "resourceIds"
                            ]
                          },
                          {
                            "type": "object",
                            "properties": {
                              "id": {
                                "description": "The webhook's ID",
                                "examples": [
                                  "WHabcd1234"
                                ],
                                "pattern": "^WH(.*)$",
                                "type": "string"
                              },
                              "userId": {
                                "description": "The unique identifier of the user that created the webhook.",
                                "examples": [
                                  "US123abc"
                                ],
                                "pattern": "^US(.*)$",
                                "type": "string"
                              },
                              "orgId": {
                                "description": "The unique identifier of the organization the webhook belongs to",
                                "examples": [
                                  "OR1223abc"
                                ],
                                "pattern": "^OR(.*)$",
                                "type": "string"
                              },
                              "label": {
                                "anyOf": [
                                  {
                                    "description": "The webhook's label.",
                                    "examples": [
                                      "my webhook label"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "status": {
                                "type": "string",
                                "enum": [
                                  "enabled",
                                  "disabled"
                                ],
                                "default": "enabled",
                                "description": "The status of the webhook.",
                                "examples": [
                                  "enabled"
                                ]
                              },
                              "url": {
                                "format": "uri",
                                "description": "The endpoint that receives events from the webhook.",
                                "examples": [
                                  "https://example.com/"
                                ],
                                "type": "string"
                              },
                              "key": {
                                "description": "Webhook key",
                                "examples": [
                                  "example-key"
                                ],
                                "type": "string"
                              },
                              "createdAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "updatedAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "deletedAt": {
                                "anyOf": [
                                  {
                                    "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                    "examples": [
                                      "2022-01-01T00:00:00Z"
                                    ],
                                    "format": "date-time",
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "events": {
                                "type": "array",
                                "items": {
                                  "type": "string",
                                  "enum": [
                                    "call.completed",
                                    "call.ringing",
                                    "call.recording.completed"
                                  ]
                                }
                              },
                              "resourceIds": {
                                "anyOf": [
                                  {
                                    "type": "array",
                                    "items": {
                                      "pattern": "^PN(.*)$",
                                      "type": "string"
                                    }
                                  },
                                  {
                                    "type": "array",
                                    "items": {
                                      "const": "*",
                                      "type": "string"
                                    }
                                  }
                                ]
                              }
                            },
                            "required": [
                              "id",
                              "userId",
                              "orgId",
                              "label",
                              "status",
                              "url",
                              "key",
                              "createdAt",
                              "updatedAt",
                              "deletedAt",
                              "events",
                              "resourceIds"
                            ]
                          },
                          {
                            "type": "object",
                            "properties": {
                              "id": {
                                "description": "The webhook's ID",
                                "examples": [
                                  "WHabcd1234"
                                ],
                                "pattern": "^WH(.*)$",
                                "type": "string"
                              },
                              "userId": {
                                "description": "The unique identifier of the user that created the webhook.",
                                "examples": [
                                  "US123abc"
                                ],
                                "pattern": "^US(.*)$",
                                "type": "string"
                              },
                              "orgId": {
                                "description": "The unique identifier of the organization the webhook belongs to",
                                "examples": [
                                  "OR1223abc"
                                ],
                                "pattern": "^OR(.*)$",
                                "type": "string"
                              },
                              "label": {
                                "anyOf": [
                                  {
                                    "description": "The webhook's label.",
                                    "examples": [
                                      "my webhook label"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "status": {
                                "type": "string",
                                "enum": [
                                  "enabled",
                                  "disabled"
                                ],
                                "default": "enabled",
                                "description": "The status of the webhook.",
                                "examples": [
                                  "enabled"
                                ]
                              },
                              "url": {
                                "format": "uri",
                                "description": "The endpoint that receives events from the webhook.",
                                "examples": [
                                  "https://example.com/"
                                ],
                                "type": "string"
                              },
                              "key": {
                                "description": "Webhook key",
                                "examples": [
                                  "example-key"
                                ],
                                "type": "string"
                              },
                              "createdAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "updatedAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "deletedAt": {
                                "anyOf": [
                                  {
                                    "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                    "examples": [
                                      "2022-01-01T00:00:00Z"
                                    ],
                                    "format": "date-time",
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "events": {
                                "minItems": 1,
                                "type": "array",
                                "items": {
                                  "type": "string",
                                  "enum": [
                                    "call.summary.completed"
                                  ]
                                }
                              },
                              "resourceIds": {
                                "anyOf": [
                                  {
                                    "type": "array",
                                    "items": {
                                      "pattern": "^PN(.*)$",
                                      "type": "string"
                                    }
                                  },
                                  {
                                    "type": "array",
                                    "items": {
                                      "const": "*",
                                      "type": "string"
                                    }
                                  }
                                ]
                              }
                            },
                            "required": [
                              "id",
                              "userId",
                              "orgId",
                              "label",
                              "status",
                              "url",
                              "key",
                              "createdAt",
                              "updatedAt",
                              "deletedAt",
                              "events",
                              "resourceIds"
                            ]
                          },
                          {
                            "type": "object",
                            "properties": {
                              "id": {
                                "description": "The webhook's ID",
                                "examples": [
                                  "WHabcd1234"
                                ],
                                "pattern": "^WH(.*)$",
                                "type": "string"
                              },
                              "userId": {
                                "description": "The unique identifier of the user that created the webhook.",
                                "examples": [
                                  "US123abc"
                                ],
                                "pattern": "^US(.*)$",
                                "type": "string"
                              },
                              "orgId": {
                                "description": "The unique identifier of the organization the webhook belongs to",
                                "examples": [
                                  "OR1223abc"
                                ],
                                "pattern": "^OR(.*)$",
                                "type": "string"
                              },
                              "label": {
                                "anyOf": [
                                  {
                                    "description": "The webhook's label.",
                                    "examples": [
                                      "my webhook label"
                                    ],
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "status": {
                                "type": "string",
                                "enum": [
                                  "enabled",
                                  "disabled"
                                ],
                                "default": "enabled",
                                "description": "The status of the webhook.",
                                "examples": [
                                  "enabled"
                                ]
                              },
                              "url": {
                                "format": "uri",
                                "description": "The endpoint that receives events from the webhook.",
                                "examples": [
                                  "https://example.com/"
                                ],
                                "type": "string"
                              },
                              "key": {
                                "description": "Webhook key",
                                "examples": [
                                  "example-key"
                                ],
                                "type": "string"
                              },
                              "createdAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "updatedAt": {
                                "description": "The date the webhook was created at, in ISO_8601 format.",
                                "examples": [
                                  "2022-01-01T00:00:00Z"
                                ],
                                "format": "date-time",
                                "type": "string"
                              },
                              "deletedAt": {
                                "anyOf": [
                                  {
                                    "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                    "examples": [
                                      "2022-01-01T00:00:00Z"
                                    ],
                                    "format": "date-time",
                                    "type": "string"
                                  },
                                  {
                                    "type": "null"
                                  }
                                ]
                              },
                              "events": {
                                "minItems": 1,
                                "type": "array",
                                "items": {
                                  "type": "string",
                                  "enum": [
                                    "call.transcript.completed"
                                  ]
                                }
                              },
                              "resourceIds": {
                                "anyOf": [
                                  {
                                    "type": "array",
                                    "items": {
                                      "pattern": "^PN(.*)$",
                                      "type": "string"
                                    }
                                  },
                                  {
                                    "type": "array",
                                    "items": {
                                      "const": "*",
                                      "type": "string"
                                    }
                                  }
                                ]
                              }
                            },
                            "required": [
                              "id",
                              "userId",
                              "orgId",
                              "label",
                              "status",
                              "url",
                              "key",
                              "createdAt",
                              "updatedAt",
                              "deletedAt",
                              "events",
                              "resourceIds"
                            ]
                          }
                        ]
                      }
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/webhooks/{id}": {
      "get": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Get a webhook by ID",
        "description": "Get a webhook by its unique identifier.",
        "operationId": "getWebhookById_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "The unique identifier of a webhook",
              "examples": [
                "WH12345"
              ],
              "pattern": "^WH(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "200": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "anyOf": [
                        {
                          "type": "object",
                          "properties": {
                            "id": {
                              "description": "The webhook's ID",
                              "examples": [
                                "WHabcd1234"
                              ],
                              "pattern": "^WH(.*)$",
                              "type": "string"
                            },
                            "userId": {
                              "description": "The unique identifier of the user that created the webhook.",
                              "examples": [
                                "US123abc"
                              ],
                              "pattern": "^US(.*)$",
                              "type": "string"
                            },
                            "orgId": {
                              "description": "The unique identifier of the organization the webhook belongs to",
                              "examples": [
                                "OR1223abc"
                              ],
                              "pattern": "^OR(.*)$",
                              "type": "string"
                            },
                            "label": {
                              "anyOf": [
                                {
                                  "description": "The webhook's label.",
                                  "examples": [
                                    "my webhook label"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "status": {
                              "type": "string",
                              "enum": [
                                "enabled",
                                "disabled"
                              ],
                              "default": "enabled",
                              "description": "The status of the webhook.",
                              "examples": [
                                "enabled"
                              ]
                            },
                            "url": {
                              "format": "uri",
                              "description": "The endpoint that receives events from the webhook.",
                              "examples": [
                                "https://example.com/"
                              ],
                              "type": "string"
                            },
                            "key": {
                              "description": "Webhook key",
                              "examples": [
                                "example-key"
                              ],
                              "type": "string"
                            },
                            "createdAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "updatedAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "deletedAt": {
                              "anyOf": [
                                {
                                  "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                  "examples": [
                                    "2022-01-01T00:00:00Z"
                                  ],
                                  "format": "date-time",
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "events": {
                              "type": "array",
                              "items": {
                                "type": "string",
                                "enum": [
                                  "message.received",
                                  "message.delivered"
                                ]
                              }
                            },
                            "resourceIds": {
                              "anyOf": [
                                {
                                  "type": "array",
                                  "items": {
                                    "pattern": "^PN(.*)$",
                                    "type": "string"
                                  }
                                },
                                {
                                  "type": "array",
                                  "items": {
                                    "const": "*",
                                    "type": "string"
                                  }
                                }
                              ]
                            }
                          },
                          "required": [
                            "id",
                            "userId",
                            "orgId",
                            "label",
                            "status",
                            "url",
                            "key",
                            "createdAt",
                            "updatedAt",
                            "deletedAt",
                            "events",
                            "resourceIds"
                          ]
                        },
                        {
                          "type": "object",
                          "properties": {
                            "id": {
                              "description": "The webhook's ID",
                              "examples": [
                                "WHabcd1234"
                              ],
                              "pattern": "^WH(.*)$",
                              "type": "string"
                            },
                            "userId": {
                              "description": "The unique identifier of the user that created the webhook.",
                              "examples": [
                                "US123abc"
                              ],
                              "pattern": "^US(.*)$",
                              "type": "string"
                            },
                            "orgId": {
                              "description": "The unique identifier of the organization the webhook belongs to",
                              "examples": [
                                "OR1223abc"
                              ],
                              "pattern": "^OR(.*)$",
                              "type": "string"
                            },
                            "label": {
                              "anyOf": [
                                {
                                  "description": "The webhook's label.",
                                  "examples": [
                                    "my webhook label"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "status": {
                              "type": "string",
                              "enum": [
                                "enabled",
                                "disabled"
                              ],
                              "default": "enabled",
                              "description": "The status of the webhook.",
                              "examples": [
                                "enabled"
                              ]
                            },
                            "url": {
                              "format": "uri",
                              "description": "The endpoint that receives events from the webhook.",
                              "examples": [
                                "https://example.com/"
                              ],
                              "type": "string"
                            },
                            "key": {
                              "description": "Webhook key",
                              "examples": [
                                "example-key"
                              ],
                              "type": "string"
                            },
                            "createdAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "updatedAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "deletedAt": {
                              "anyOf": [
                                {
                                  "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                  "examples": [
                                    "2022-01-01T00:00:00Z"
                                  ],
                                  "format": "date-time",
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "events": {
                              "type": "array",
                              "items": {
                                "type": "string",
                                "enum": [
                                  "call.completed",
                                  "call.ringing",
                                  "call.recording.completed"
                                ]
                              }
                            },
                            "resourceIds": {
                              "anyOf": [
                                {
                                  "type": "array",
                                  "items": {
                                    "pattern": "^PN(.*)$",
                                    "type": "string"
                                  }
                                },
                                {
                                  "type": "array",
                                  "items": {
                                    "const": "*",
                                    "type": "string"
                                  }
                                }
                              ]
                            }
                          },
                          "required": [
                            "id",
                            "userId",
                            "orgId",
                            "label",
                            "status",
                            "url",
                            "key",
                            "createdAt",
                            "updatedAt",
                            "deletedAt",
                            "events",
                            "resourceIds"
                          ]
                        },
                        {
                          "type": "object",
                          "properties": {
                            "id": {
                              "description": "The webhook's ID",
                              "examples": [
                                "WHabcd1234"
                              ],
                              "pattern": "^WH(.*)$",
                              "type": "string"
                            },
                            "userId": {
                              "description": "The unique identifier of the user that created the webhook.",
                              "examples": [
                                "US123abc"
                              ],
                              "pattern": "^US(.*)$",
                              "type": "string"
                            },
                            "orgId": {
                              "description": "The unique identifier of the organization the webhook belongs to",
                              "examples": [
                                "OR1223abc"
                              ],
                              "pattern": "^OR(.*)$",
                              "type": "string"
                            },
                            "label": {
                              "anyOf": [
                                {
                                  "description": "The webhook's label.",
                                  "examples": [
                                    "my webhook label"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "status": {
                              "type": "string",
                              "enum": [
                                "enabled",
                                "disabled"
                              ],
                              "default": "enabled",
                              "description": "The status of the webhook.",
                              "examples": [
                                "enabled"
                              ]
                            },
                            "url": {
                              "format": "uri",
                              "description": "The endpoint that receives events from the webhook.",
                              "examples": [
                                "https://example.com/"
                              ],
                              "type": "string"
                            },
                            "key": {
                              "description": "Webhook key",
                              "examples": [
                                "example-key"
                              ],
                              "type": "string"
                            },
                            "createdAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "updatedAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "deletedAt": {
                              "anyOf": [
                                {
                                  "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                  "examples": [
                                    "2022-01-01T00:00:00Z"
                                  ],
                                  "format": "date-time",
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "events": {
                              "minItems": 1,
                              "type": "array",
                              "items": {
                                "type": "string",
                                "enum": [
                                  "call.summary.completed"
                                ]
                              }
                            },
                            "resourceIds": {
                              "anyOf": [
                                {
                                  "type": "array",
                                  "items": {
                                    "pattern": "^PN(.*)$",
                                    "type": "string"
                                  }
                                },
                                {
                                  "type": "array",
                                  "items": {
                                    "const": "*",
                                    "type": "string"
                                  }
                                }
                              ]
                            }
                          },
                          "required": [
                            "id",
                            "userId",
                            "orgId",
                            "label",
                            "status",
                            "url",
                            "key",
                            "createdAt",
                            "updatedAt",
                            "deletedAt",
                            "events",
                            "resourceIds"
                          ]
                        },
                        {
                          "type": "object",
                          "properties": {
                            "id": {
                              "description": "The webhook's ID",
                              "examples": [
                                "WHabcd1234"
                              ],
                              "pattern": "^WH(.*)$",
                              "type": "string"
                            },
                            "userId": {
                              "description": "The unique identifier of the user that created the webhook.",
                              "examples": [
                                "US123abc"
                              ],
                              "pattern": "^US(.*)$",
                              "type": "string"
                            },
                            "orgId": {
                              "description": "The unique identifier of the organization the webhook belongs to",
                              "examples": [
                                "OR1223abc"
                              ],
                              "pattern": "^OR(.*)$",
                              "type": "string"
                            },
                            "label": {
                              "anyOf": [
                                {
                                  "description": "The webhook's label.",
                                  "examples": [
                                    "my webhook label"
                                  ],
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "status": {
                              "type": "string",
                              "enum": [
                                "enabled",
                                "disabled"
                              ],
                              "default": "enabled",
                              "description": "The status of the webhook.",
                              "examples": [
                                "enabled"
                              ]
                            },
                            "url": {
                              "format": "uri",
                              "description": "The endpoint that receives events from the webhook.",
                              "examples": [
                                "https://example.com/"
                              ],
                              "type": "string"
                            },
                            "key": {
                              "description": "Webhook key",
                              "examples": [
                                "example-key"
                              ],
                              "type": "string"
                            },
                            "createdAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "updatedAt": {
                              "description": "The date the webhook was created at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            "deletedAt": {
                              "anyOf": [
                                {
                                  "description": "The date the webhook was deleted at, in ISO_8601 format.",
                                  "examples": [
                                    "2022-01-01T00:00:00Z"
                                  ],
                                  "format": "date-time",
                                  "type": "string"
                                },
                                {
                                  "type": "null"
                                }
                              ]
                            },
                            "events": {
                              "minItems": 1,
                              "type": "array",
                              "items": {
                                "type": "string",
                                "enum": [
                                  "call.transcript.completed"
                                ]
                              }
                            },
                            "resourceIds": {
                              "anyOf": [
                                {
                                  "type": "array",
                                  "items": {
                                    "pattern": "^PN(.*)$",
                                    "type": "string"
                                  }
                                },
                                {
                                  "type": "array",
                                  "items": {
                                    "const": "*",
                                    "type": "string"
                                  }
                                }
                              ]
                            }
                          },
                          "required": [
                            "id",
                            "userId",
                            "orgId",
                            "label",
                            "status",
                            "url",
                            "key",
                            "createdAt",
                            "updatedAt",
                            "deletedAt",
                            "events",
                            "resourceIds"
                          ]
                        }
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Delete a webhook by ID",
        "description": "Delete a webhook by its unique identifier.",
        "operationId": "deleteWebhookById_v1",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "description": "The unique identifier of a webhook",
              "examples": [
                "WH12345"
              ],
              "pattern": "^WH(.*)$",
              "type": "string"
            }
          }
        ],
        "security": [
          {
            "apiKey": []
          }
        ],
        "responses": {
          "204": {
            "description": "Success"
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/webhooks/messages": {
      "post": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Create a new webhook for messages",
        "description": "Creates a new webhook that triggers on events from messages.",
        "operationId": "createMessageWebhook_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "events": {
                    "type": "array",
                    "items": {
                      "type": "string",
                      "enum": [
                        "message.received",
                        "message.delivered"
                      ]
                    }
                  },
                  "label": {
                    "description": "Webhook's label",
                    "examples": [
                      "my webhook label"
                    ],
                    "type": "string"
                  },
                  "resourceIds": {
                    "anyOf": [
                      {
                        "type": "array",
                        "items": {
                          "pattern": "^PN(.*)$",
                          "type": "string"
                        }
                      },
                      {
                        "type": "array",
                        "items": {
                          "const": "*",
                          "type": "string"
                        }
                      }
                    ]
                  },
                  "status": {
                    "type": "string",
                    "enum": [
                      "enabled",
                      "disabled"
                    ],
                    "default": "enabled",
                    "description": "The status of the webhook.",
                    "examples": [
                      "enabled"
                    ]
                  },
                  "url": {
                    "format": "uri",
                    "description": "The endpoint that receives events from the webhook.",
                    "examples": [
                      "https://example.com"
                    ],
                    "type": "string"
                  },
                  "userId": {
                    "description": "The unique identifier of the user that creates the webhook. If not provided, default to workspace owner.",
                    "examples": [
                      "US123abc"
                    ],
                    "pattern": "^US(.*)$",
                    "type": "string"
                  }
                },
                "required": [
                  "events",
                  "url"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The webhook's ID",
                          "examples": [
                            "WHabcd1234"
                          ],
                          "pattern": "^WH(.*)$",
                          "type": "string"
                        },
                        "userId": {
                          "description": "The unique identifier of the user that created the webhook.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        },
                        "orgId": {
                          "description": "The unique identifier of the organization the webhook belongs to",
                          "examples": [
                            "OR1223abc"
                          ],
                          "pattern": "^OR(.*)$",
                          "type": "string"
                        },
                        "label": {
                          "anyOf": [
                            {
                              "description": "The webhook's label.",
                              "examples": [
                                "my webhook label"
                              ],
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "enabled",
                            "disabled"
                          ],
                          "default": "enabled",
                          "description": "The status of the webhook.",
                          "examples": [
                            "enabled"
                          ]
                        },
                        "url": {
                          "format": "uri",
                          "description": "The endpoint that receives events from the webhook.",
                          "examples": [
                            "https://example.com/"
                          ],
                          "type": "string"
                        },
                        "key": {
                          "description": "Webhook key",
                          "examples": [
                            "example-key"
                          ],
                          "type": "string"
                        },
                        "createdAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "deletedAt": {
                          "anyOf": [
                            {
                              "description": "The date the webhook was deleted at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "events": {
                          "type": "array",
                          "items": {
                            "type": "string",
                            "enum": [
                              "message.received",
                              "message.delivered"
                            ]
                          }
                        },
                        "resourceIds": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "pattern": "^PN(.*)$",
                                "type": "string"
                              }
                            },
                            {
                              "type": "array",
                              "items": {
                                "const": "*",
                                "type": "string"
                              }
                            }
                          ]
                        }
                      },
                      "required": [
                        "id",
                        "userId",
                        "orgId",
                        "label",
                        "status",
                        "url",
                        "key",
                        "createdAt",
                        "updatedAt",
                        "deletedAt",
                        "events",
                        "resourceIds"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/webhooks/calls": {
      "post": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Create a new webhook for calls",
        "description": "Creates a new webhook that triggers on events from calls.",
        "operationId": "createCallWebhook_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "url": {
                    "format": "uri",
                    "description": "The endpoint that receives events from the webhook.",
                    "examples": [
                      "https://example.com/"
                    ],
                    "type": "string"
                  },
                  "events": {
                    "type": "array",
                    "items": {
                      "type": "string",
                      "enum": [
                        "call.completed",
                        "call.ringing",
                        "call.recording.completed"
                      ]
                    }
                  },
                  "resourceIds": {
                    "anyOf": [
                      {
                        "type": "array",
                        "items": {
                          "pattern": "^PN(.*)$",
                          "type": "string"
                        }
                      },
                      {
                        "type": "array",
                        "items": {
                          "const": "*",
                          "type": "string"
                        }
                      }
                    ]
                  },
                  "userId": {
                    "description": "The unique identifier of the user that creates the webhook. If not provided, default to workspace owner.",
                    "examples": [
                      "US123abc"
                    ],
                    "pattern": "^US(.*)$",
                    "type": "string"
                  },
                  "label": {
                    "description": "Webhook's label",
                    "examples": [
                      "my webhook label"
                    ],
                    "type": "string"
                  },
                  "status": {
                    "type": "string",
                    "enum": [
                      "enabled",
                      "disabled"
                    ],
                    "default": "enabled",
                    "description": "The status of the webhook.",
                    "examples": [
                      "enabled"
                    ]
                  }
                },
                "required": [
                  "url",
                  "events"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The webhook's ID",
                          "examples": [
                            "WHabcd1234"
                          ],
                          "pattern": "^WH(.*)$",
                          "type": "string"
                        },
                        "userId": {
                          "description": "The unique identifier of the user that created the webhook.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        },
                        "orgId": {
                          "description": "The unique identifier of the organization the webhook belongs to",
                          "examples": [
                            "OR1223abc"
                          ],
                          "pattern": "^OR(.*)$",
                          "type": "string"
                        },
                        "label": {
                          "anyOf": [
                            {
                              "description": "The webhook's label.",
                              "examples": [
                                "my webhook label"
                              ],
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "enabled",
                            "disabled"
                          ],
                          "default": "enabled",
                          "description": "The status of the webhook.",
                          "examples": [
                            "enabled"
                          ]
                        },
                        "url": {
                          "format": "uri",
                          "description": "The endpoint that receives events from the webhook.",
                          "examples": [
                            "https://example.com/"
                          ],
                          "type": "string"
                        },
                        "key": {
                          "description": "Webhook key",
                          "examples": [
                            "example-key"
                          ],
                          "type": "string"
                        },
                        "createdAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "deletedAt": {
                          "anyOf": [
                            {
                              "description": "The date the webhook was deleted at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "events": {
                          "type": "array",
                          "items": {
                            "type": "string",
                            "enum": [
                              "call.completed",
                              "call.ringing",
                              "call.recording.completed"
                            ]
                          }
                        },
                        "resourceIds": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "pattern": "^PN(.*)$",
                                "type": "string"
                              }
                            },
                            {
                              "type": "array",
                              "items": {
                                "const": "*",
                                "type": "string"
                              }
                            }
                          ]
                        }
                      },
                      "required": [
                        "id",
                        "userId",
                        "orgId",
                        "label",
                        "status",
                        "url",
                        "key",
                        "createdAt",
                        "updatedAt",
                        "deletedAt",
                        "events",
                        "resourceIds"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/webhooks/call-summaries": {
      "post": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Create a new webhook for call summaries",
        "description": "Creates a new webhook that triggers on events from call summaries.",
        "operationId": "createCallSummaryWebhook_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "events": {
                    "minItems": 1,
                    "type": "array",
                    "items": {
                      "type": "string",
                      "enum": [
                        "call.summary.completed"
                      ]
                    }
                  },
                  "label": {
                    "description": "Webhook's label",
                    "examples": [
                      "my webhook label"
                    ],
                    "type": "string"
                  },
                  "resourceIds": {
                    "anyOf": [
                      {
                        "type": "array",
                        "items": {
                          "pattern": "^PN(.*)$",
                          "type": "string"
                        }
                      },
                      {
                        "type": "array",
                        "items": {
                          "const": "*",
                          "type": "string"
                        }
                      }
                    ]
                  },
                  "status": {
                    "type": "string",
                    "enum": [
                      "enabled",
                      "disabled"
                    ],
                    "default": "enabled",
                    "description": "The status of the webhook.",
                    "examples": [
                      "enabled"
                    ]
                  },
                  "url": {
                    "format": "uri",
                    "description": "The endpoint that receives events from the webhook.",
                    "examples": [
                      "https://example.com"
                    ],
                    "type": "string"
                  },
                  "userId": {
                    "description": "The unique identifier of the user that creates the webhook. If not provided, default to workspace owner.",
                    "examples": [
                      "US123abc"
                    ],
                    "pattern": "^US(.*)$",
                    "type": "string"
                  }
                },
                "required": [
                  "events",
                  "url"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The webhook's ID",
                          "examples": [
                            "WHabcd1234"
                          ],
                          "pattern": "^WH(.*)$",
                          "type": "string"
                        },
                        "userId": {
                          "description": "The unique identifier of the user that created the webhook.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        },
                        "orgId": {
                          "description": "The unique identifier of the organization the webhook belongs to",
                          "examples": [
                            "OR1223abc"
                          ],
                          "pattern": "^OR(.*)$",
                          "type": "string"
                        },
                        "label": {
                          "anyOf": [
                            {
                              "description": "The webhook's label.",
                              "examples": [
                                "my webhook label"
                              ],
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "enabled",
                            "disabled"
                          ],
                          "default": "enabled",
                          "description": "The status of the webhook.",
                          "examples": [
                            "enabled"
                          ]
                        },
                        "url": {
                          "format": "uri",
                          "description": "The endpoint that receives events from the webhook.",
                          "examples": [
                            "https://example.com/"
                          ],
                          "type": "string"
                        },
                        "key": {
                          "description": "Webhook key",
                          "examples": [
                            "example-key"
                          ],
                          "type": "string"
                        },
                        "createdAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "deletedAt": {
                          "anyOf": [
                            {
                              "description": "The date the webhook was deleted at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "events": {
                          "minItems": 1,
                          "type": "array",
                          "items": {
                            "type": "string",
                            "enum": [
                              "call.summary.completed"
                            ]
                          }
                        },
                        "resourceIds": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "pattern": "^PN(.*)$",
                                "type": "string"
                              }
                            },
                            {
                              "type": "array",
                              "items": {
                                "const": "*",
                                "type": "string"
                              }
                            }
                          ]
                        }
                      },
                      "required": [
                        "id",
                        "userId",
                        "orgId",
                        "label",
                        "status",
                        "url",
                        "key",
                        "createdAt",
                        "updatedAt",
                        "deletedAt",
                        "events",
                        "resourceIds"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    },
    "/v1/webhooks/call-transcripts": {
      "post": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Create a new webhook for call transcripts",
        "description": "Creates a new webhook that triggers on events from call transcripts.",
        "operationId": "createCallTranscriptWebhook_v1",
        "parameters": [],
        "security": [
          {
            "apiKey": []
          }
        ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "events": {
                    "minItems": 1,
                    "type": "array",
                    "items": {
                      "type": "string",
                      "enum": [
                        "call.transcript.completed"
                      ]
                    }
                  },
                  "label": {
                    "description": "The webhook's label.",
                    "examples": [
                      "my webhook label"
                    ],
                    "type": "string"
                  },
                  "resourceIds": {
                    "anyOf": [
                      {
                        "type": "array",
                        "items": {
                          "pattern": "^PN(.*)$",
                          "type": "string"
                        }
                      },
                      {
                        "type": "array",
                        "items": {
                          "const": "*",
                          "type": "string"
                        }
                      }
                    ]
                  },
                  "status": {
                    "type": "string",
                    "enum": [
                      "enabled",
                      "disabled"
                    ],
                    "description": "The status of the webhook.",
                    "examples": [
                      "enabled"
                    ]
                  },
                  "url": {
                    "format": "uri",
                    "description": "The endpoint that receives events from the webhook.",
                    "examples": [
                      "https://example.com"
                    ],
                    "type": "string"
                  },
                  "userId": {
                    "description": "The ID of the user that creates the webhook. If not provided, default to workspace owner.",
                    "examples": [
                      "US123abc"
                    ],
                    "pattern": "^US(.*)$",
                    "type": "string"
                  }
                },
                "required": [
                  "events",
                  "url"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Success",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "data": {
                      "type": "object",
                      "properties": {
                        "id": {
                          "description": "The webhook's ID",
                          "examples": [
                            "WHabcd1234"
                          ],
                          "pattern": "^WH(.*)$",
                          "type": "string"
                        },
                        "userId": {
                          "description": "The unique identifier of the user that created the webhook.",
                          "examples": [
                            "US123abc"
                          ],
                          "pattern": "^US(.*)$",
                          "type": "string"
                        },
                        "orgId": {
                          "description": "The unique identifier of the organization the webhook belongs to",
                          "examples": [
                            "OR1223abc"
                          ],
                          "pattern": "^OR(.*)$",
                          "type": "string"
                        },
                        "label": {
                          "anyOf": [
                            {
                              "description": "The webhook's label.",
                              "examples": [
                                "my webhook label"
                              ],
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "status": {
                          "type": "string",
                          "enum": [
                            "enabled",
                            "disabled"
                          ],
                          "default": "enabled",
                          "description": "The status of the webhook.",
                          "examples": [
                            "enabled"
                          ]
                        },
                        "url": {
                          "format": "uri",
                          "description": "The endpoint that receives events from the webhook.",
                          "examples": [
                            "https://example.com/"
                          ],
                          "type": "string"
                        },
                        "key": {
                          "description": "Webhook key",
                          "examples": [
                            "example-key"
                          ],
                          "type": "string"
                        },
                        "createdAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "updatedAt": {
                          "description": "The date the webhook was created at, in ISO_8601 format.",
                          "examples": [
                            "2022-01-01T00:00:00Z"
                          ],
                          "format": "date-time",
                          "type": "string"
                        },
                        "deletedAt": {
                          "anyOf": [
                            {
                              "description": "The date the webhook was deleted at, in ISO_8601 format.",
                              "examples": [
                                "2022-01-01T00:00:00Z"
                              ],
                              "format": "date-time",
                              "type": "string"
                            },
                            {
                              "type": "null"
                            }
                          ]
                        },
                        "events": {
                          "minItems": 1,
                          "type": "array",
                          "items": {
                            "type": "string",
                            "enum": [
                              "call.transcript.completed"
                            ]
                          }
                        },
                        "resourceIds": {
                          "anyOf": [
                            {
                              "type": "array",
                              "items": {
                                "pattern": "^PN(.*)$",
                                "type": "string"
                              }
                            },
                            {
                              "type": "array",
                              "items": {
                                "const": "*",
                                "type": "string"
                              }
                            }
                          ]
                        }
                      },
                      "required": [
                        "id",
                        "userId",
                        "orgId",
                        "label",
                        "status",
                        "url",
                        "key",
                        "createdAt",
                        "updatedAt",
                        "deletedAt",
                        "events",
                        "resourceIds"
                      ]
                    }
                  },
                  "required": [
                    "data"
                  ]
                }
              }
            }
          },
          "400": {
            "description": "Invalid Version",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0305400",
                      "type": "string"
                    },
                    "status": {
                      "const": 400,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Invalid Version",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    },
                    "description": {
                      "const": "Invalid Version",
                      "type": "string"
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title",
                    "description"
                  ]
                }
              }
            }
          },
          "401": {
            "description": "Unauthorized",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300401",
                      "type": "string"
                    },
                    "status": {
                      "const": 401,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unauthorized",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "403": {
            "description": "Forbidden",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300403",
                      "type": "string"
                    },
                    "status": {
                      "const": 403,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Forbidden",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "404": {
            "description": "Not Found",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0300404",
                      "type": "string"
                    },
                    "status": {
                      "const": 404,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Not Found",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          },
          "500": {
            "description": "Unknown Error",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "message": {
                      "type": "string"
                    },
                    "code": {
                      "const": "0301500",
                      "type": "string"
                    },
                    "status": {
                      "const": 500,
                      "type": "number"
                    },
                    "docs": {
                      "const": "https://openphone.com/docs",
                      "type": "string"
                    },
                    "title": {
                      "const": "Unknown",
                      "type": "string"
                    },
                    "trace": {
                      "type": "string"
                    },
                    "errors": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "path": {
                            "type": "string"
                          },
                          "message": {
                            "type": "string"
                          },
                          "value": {},
                          "schema": {
                            "type": "object",
                            "properties": {
                              "type": {
                                "type": "string"
                              }
                            },
                            "required": [
                              "type"
                            ]
                          }
                        },
                        "required": [
                          "path",
                          "message",
                          "schema"
                        ]
                      }
                    }
                  },
                  "required": [
                    "message",
                    "code",
                    "status",
                    "docs",
                    "title"
                  ]
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "ListPhoneNumbersResponse": {
        "type": "object",
        "properties": {
          "data": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "id": {
                  "description": "The unique identifier of OpenPhone phone number.",
                  "examples": [
                    "PN123bc"
                  ],
                  "pattern": "^PN(.*)$",
                  "type": "string"
                },
                "groupId": {
                  "description": "The unique identifier of the group to which the OpenPhone number belongs.",
                  "examples": [
                    "1234"
                  ],
                  "type": "string"
                },
                "createdAt": {
                  "description": "Timestamp of when the phone number was added to the account in ISO 8601 format.",
                  "examples": [
                    " '2022-01-01T00:00:00Z'"
                  ],
                  "type": "string"
                },
                "updatedAt": {
                  "description": "Timestamp of the last update to the phone number's details in ISO 8601 format.",
                  "examples": [
                    " '2022-01-01T00:00:00Z'"
                  ],
                  "type": "string"
                },
                "name": {
                  "description": "The display name of the phone number",
                  "examples": [
                    "My phone number"
                  ],
                  "type": "string"
                },
                "number": {
                  "pattern": "^\\+[1-9]\\d{1,14}$",
                  "description": "A phone number in E.164 format, including the country code.",
                  "examples": [
                    "+15555555555"
                  ],
                  "type": "string"
                },
                "formattedNumber": {
                  "anyOf": [
                    {
                      "description": "A human-readable representation of a phone number.",
                      "examples": [
                        "+15555555555"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ]
                },
                "forward": {
                  "anyOf": [
                    {
                      "description": "Forwarding number for incoming calls, null if no forwarding number is configured.",
                      "examples": [
                        "+15555555555"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ]
                },
                "portRequestId": {
                  "anyOf": [
                    {
                      "description": "Unique identifier for the phone number’s porting request, if applicable.",
                      "examples": [
                        "123abc"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ]
                },
                "portingStatus": {
                  "anyOf": [
                    {
                      "description": "Current status of the porting process, if applicable.",
                      "examples": [
                        "completed"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ]
                },
                "symbol": {
                  "anyOf": [
                    {
                      "description": "Custom symbol or emoji associated with the phone number.",
                      "examples": [
                        "🏡"
                      ],
                      "type": "string"
                    },
                    {
                      "type": "null"
                    }
                  ]
                },
                "users": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "email": {
                        "type": "string"
                      },
                      "firstName": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "groupId": {
                        "type": "string"
                      },
                      "id": {
                        "pattern": "^US(.*)$",
                        "type": "string"
                      },
                      "lastName": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "null"
                          }
                        ]
                      },
                      "role": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "email",
                      "firstName",
                      "groupId",
                      "id",
                      "lastName",
                      "role"
                    ]
                  }
                },
                "restrictions": {
                  "type": "object",
                  "properties": {
                    "messaging": {
                      "type": "object",
                      "properties": {
                        "CA": {
                          "type": "string",
                          "enum": [
                            "restricted",
                            "unrestricted"
                          ],
                          "description": "The phone-number usage restriction status for a specific region",
                          "examples": [
                            "unrestricted"
                          ]
                        },
                        "US": {
                          "type": "string",
                          "enum": [
                            "restricted",
                            "unrestricted"
                          ],
                          "description": "The phone-number usage restriction status for a specific region",
                          "examples": [
                            "unrestricted"
                          ]
                        },
                        "Intl": {
                          "type": "string",
                          "enum": [
                            "restricted",
                            "unrestricted"
                          ],
                          "description": "The phone-number usage restriction status for a specific region",
                          "examples": [
                            "unrestricted"
                          ]
                        }
                      },
                      "required": [
                        "CA",
                        "US",
                        "Intl"
                      ]
                    },
                    "calling": {
                      "type": "object",
                      "properties": {
                        "CA": {
                          "type": "string",
                          "enum": [
                            "restricted",
                            "unrestricted"
                          ],
                          "description": "The phone-number usage restriction status for a specific region",
                          "examples": [
                            "unrestricted"
                          ]
                        },
                        "US": {
                          "type": "string",
                          "enum": [
                            "restricted",
                            "unrestricted"
                          ],
                          "description": "The phone-number usage restriction status for a specific region",
                          "examples": [
                            "unrestricted"
                          ]
                        },
                        "Intl": {
                          "type": "string",
                          "enum": [
                            "restricted",
                            "unrestricted"
                          ],
                          "description": "The phone-number usage restriction status for a specific region",
                          "examples": [
                            "unrestricted"
                          ]
                        }
                      },
                      "required": [
                        "CA",
                        "US",
                        "Intl"
                      ]
                    }
                  },
                  "required": [
                    "messaging",
                    "calling"
                  ]
                }
              },
              "required": [
                "id",
                "groupId",
                "createdAt",
                "updatedAt",
                "name",
                "number",
                "formattedNumber",
                "forward",
                "portRequestId",
                "portingStatus",
                "symbol",
                "users",
                "restrictions"
              ]
            }
          }
        },
        "required": [
          "data"
        ]
      }
    },
    "securitySchemes": {
      "apiKey": {
        "type": "apiKey",
        "name": "Authorization",
        "in": "header"
      }
    }
  },
  "servers": [
    {
      "url": "https://api.openphone.com",
      "description": "Production server"
    }
  ],
  "tags": [
    {
      "name": "Calls",
      "description": "Operations related to calls"
    },
    {
      "name": "Call Summaries",
      "description": "Operations related to call summaries"
    },
    {
      "name": "Call Transcripts",
      "description": "Operations related to call transcripts"
    },
    {
      "name": "Contacts",
      "description": "Operations related to contacts"
    },
    {
      "name": "Conversations",
      "description": "Operations related to conversations"
    },
    {
      "name": "Messages",
      "description": "Operations related to text messages"
    },
    {
      "name": "Phone Numbers",
      "description": "Operations related to phone numbers"
    },
    {
      "name": "Webhooks",
      "description": "Operations related to webhooks"
    }
  ],
  "security": [
    {
      "apiKey": []
    }
  ],
  "x-kong-name": "public_api",
  "x-kong-service-defaults": {
    "retries": 10,
    "connect_timeout": 30000,
    "write_timeout": 30000,
    "read_timeout": 30000
  },
  "x-kong-route-defaults": {
    "preserve_host": true
  },
  "x-kong-plugin-key-auth": {
    "config": {
      "key_names": [
        "Authorization"
      ]
    }
  },
  "x-kong-plugin-rate-limiting": {
    "config": {
      "second": 10,
      "policy": "local",
      "limit_by": "consumer",
      "fault_tolerant": true
    }
  }
}