<?php

/**
 * api.php
 *
 * REST application for Project Y
 *
 * @version     0.0.1
 */
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: GET,POST,PUT,DELETE');
header('Access-Control-Allow-Headers: X-Requested-With, Authorization, Content-Type');

require_once('helpers/includes.php');

use Firebase\JWT\JWT;

$serverName = 'http://guruma.pl'; // todo change
$key = 'co/Xjz6t0QRLrRLVNsDJwMaBnTqu9zRGFDBjgIpFRIXC2gLuxfMAlEtyQAQAk7gOv62/l+OR/ay0/DcT+gGfNg==2';
$algorithm = 'HS512';
$action = '';
if (isset($_GET['action'])) {
    $action = $_GET['action'];
}
$method = '';
if (isset($_SERVER['REQUEST_METHOD'])) {
    $method = $_SERVER['REQUEST_METHOD'];
}

try {
    switch ($action) {
        case 'auth':
            if ($_SERVER['REQUEST_METHOD'] == 'GET') {
                $username = filter_input(INPUT_GET, 'username', FILTER_SANITIZE_EMAIL);
                $password = isset($_GET['password']) ? htmlspecialchars($_GET['password']) : '';

                if ($username && $password) {
                    try {
                        $users = User::checkLogin($username, $password);
                        if ($users == false) {
                            response(401, ['error' => true, 'message' => 'Invalid email or password!']);
                        } else {
                            $tokenId = base64_encode(random_bytes(32));
                            $issuedAt = time();
                            $notBefore = $issuedAt;
                            $expire = $notBefore + (86400 * 7); // 7 days

                            /*

                            * Create the token as an array
                            */
                            $data = [
                                'iat' => $issuedAt,         // Issued at: time when the token was generated
                                'jti' => $tokenId,          // Json Token Id: an unique identifier for the token
                                'iss' => $serverName,       // Issuer
                                'nbf' => $notBefore,        // Not before
                                'exp' => $expire,           // Expire
                                'data' => [                  // Data related to the signer user
                                    'userId' => 1, // userid from the users table - dane z DB
                                    'userName' => 'admin', // User name
                                ]
                            ];
                            /*
                            * Extract the key, which is coming from the config file.
                            *
                            * Best suggestion is the key to be a binary string and
                            * store it in encoded in a config file.
                            *
                            * Can be generated with base64_encode(openssl_random_pseudo_bytes(64));
                            *
                            * keep it secure! You'll need the exact key to verify the
                            * token later.
                            */

                            /*
                            * Encode the array to a JWT string.
                            * Second parameter is the key to encode the token.
                            *
                            * The output string can be validated at http://jwt.io/
                            */
                            $jwt = JWT::encode(
                                $data,      //Data to be encoded in the JWT
                                $key, // The signing key
                                $algorithm  // Algorithm used to sign the token, see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3
                            );

                            $unencodedArray = [
                                'message' => 'Logged in Successfully',
                                'jwt' => $jwt,
                                'username' => $username
                            ];
                            echo json_encode($unencodedArray);
                        }
                    } catch (Exception $e) {
                        response(true, ['error' => true, 'message' => 'Invalid Server Error!'], 500);
                    }
                } else {
                    response(true, ['error' => true, 'message' => 'Invalid request!'], 400);
                }
            } else {
                response(true, ['error' => true, 'message' => 'This method is not allowed!'], 405);
            }
            break;
        case 'users':
            if ($method == 'GET') {
                $token = getToken($key, $algorithm);
                try {
                    if (isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $result = new User();
                        $result->getInstanceById($id);
                        if ($result === false) {
                            response(true, ['message' => 'Failed to return user record with id ' . $id], 404);
                        } else {
                            response(false, ['data' => $result]);
                        }
                    } else {
                        $users = User::getAll();
                        response(false, ['data' => $users]);
                    }
                } catch (Exception $e) {
                    response(true, ['error' => true, 'message' => 'Invalid Server Error!'], 500);
                }
            } else if ($method == 'POST') {
                $token = getToken($key, $algorithm);
                try {
                    $body = json_decode(file_get_contents('php://input'), true);
                    $userRecord = new User();
                    if (isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $result = new User();
                        $result->getInstanceById($id);
                    } else {
                        foreach ($body as $key => $value) {
                            if ($key === 'username' && $userRecord->getId($value) != false) {
                                response(true, ['message' => 'This Username already exists!'], 400);
                            } else if ($key === 'email' && !empty($value) && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                                response(true, ['message' => 'Given email is incorrect!'], 400);
                            } else if ($key === 'password') {
                                if (!User::validatePassword($value)) {
                                    response(true, ['message' => 'Password must be minimum 6 characters long and contains lower and upper case letters and numbers!'], 400);
                                }
                            }
                            $userRecord->set($key, $value);
                        }
                        if (!$userRecord->save()) {
                            response(true, ['message' => 'Failed to create user.'], 500);
                        } else {
                            response(false, ['message' => 'Successfully created user with id ' . $userRecord->get('id')]);
                        }
                    }
                } catch (Exception $e) {
                    response(true, ['message' => $e->getMessage()], 500);
                }
            } else if ($method == 'PUT') {
                $token = getToken($key, $algorithm);
                try {
                    $body = json_decode(file_get_contents('php://input'), true);
                    if (isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $userRecord = new User();
                        $userRecord->getInstanceById($id);
                        foreach ($body as $property => $value) {
                            if (property_exists($userRecord, $property)) {
                                $userRecord->$property = $value;
                            }
                            if ($property === 'password') {
                                if (!User::validatePassword($value)) {
                                    response(true, ['message' => 'Password must be minimum 6 characters long and contains lower and upper case letters and numbers!'], 400);
                                }
                            }
                        }
                        $userRecord->save();
                        http_response_code(200);
                        echo json_encode(array("message" => 'Successfully updated user with id ' . $userRecord->get('id')));
                    } else {
                        http_response_code(400);
                        echo json_encode(array("message" => "Bad request. User ID is missing."));
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode(array("message" => "Server error. Failed to update user."));
                }
            } else if ($method == 'DELETE') {
                $token = getToken($key, $algorithm);
                try {
                    $id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
                    if ($id) {
                        $user = new User();
                        $user->getInstanceById($id);
                        $user->remove();
                        response(false, ['message' => 'Successfully deleted user with id ' . $id]);
                    } else {
                        response(true, ['message' => "User id doesn't exist!"], 404);
                    }
                } catch (Exception $e) {
                    response(true, ['error' => true, 'message' => $e->getMessage()], 400);
                }
            } else if ($method !== 'OPTIONS') {
                response(true, ['message' => 'Invalid command!'], 400);
            }
            break;
        case 'dispose':
            if ($method == 'GET') {
                $token = getToken($key, $algorithm);
                try {
                    if (isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $result = new Dispose();
                        $result->getInstanceById($id);
                        if ($result === false) {
                            response(true, ['message' => 'Failed to return dispose record with id ' . $id], 404);
                        } else {
                            response(false, ['data' => $result]);
                        }
                    } else {
                        $Disposes = Dispose::getAll();
                        response(false, ['data' => $Disposes]);
                    }
                } catch (Exception $e) {
                    response(true, ['error' => true, 'message' => 'Invalid Server Error!'], 500);
                }
            } else if ($method == 'POST') {
                $token = getToken($key, $algorithm);
                try {
                    $body = json_decode(file_get_contents('php://input'), true);
                    $disposeRecord = new Dispose();
                    if (isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $result = new Dispose();
                        $result->getInstanceById($id);
                    } else {
                        foreach ($body as $key => $value) {
                            $disposeRecord->set($key, $value);
                            if ($key === 'quantity' && !Dispose::validateQuantity($value)) {
                                response(true, ['message' => 'Quantity must be a numeric value!'], 400);
                            } else if ($key === 'date' && !Dispose::validateDate($value)) {
                                response(true, ['message' => 'Data must be in a correct format (Y-m-d)!'], 400);
                            }
                        }
                        if (!$disposeRecord->save()) {
                            response(true, ['message' => 'Failed to create dispose.'], 500);
                        } else {
                            response(false, ['message' => 'Successfully created dispose with id ' . $disposeRecord->get('id')]);
                        }
                    }
                } catch (Exception $e) {
                    response(true, ['message' => $e->getMessage()], 500);
                }
            } else if ($method == 'PUT') {
                $token = getToken($key, $algorithm);
                try {
                    $body = json_decode(file_get_contents('php://input'), true);
                    if (isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $disposeRecord = new Dispose();
                        $disposeRecord->getInstanceById($id);
                        foreach ($body as $property => $value) {
                            if (property_exists($disposeRecord, $property)) {
                                $disposeRecord->$property = $value;
                            } else if ($key === 'quantity' && !Dispose::validateQuantity($value)) {
                                response(true, ['message' => 'Quantity must be a numeric value!'], 400);
                            } else if ($key === 'date' && !Dispose::validateDate($value)) {
                                response(true, ['message' => 'Data must be in a correct format (Y-m-d)!'], 400);
                            }
                        }
                        $disposeRecord->save();
                        http_response_code(200);
                        echo json_encode(array("message" => 'Successfully updated dispose with id ' . $disposeRecord->get('id')));
                    } else {
                        http_response_code(400);
                        echo json_encode(array("message" => "Bad request. Dispose ID is missing."));
                    }
                } catch (Exception $e) {
                    http_response_code(500);
                    echo json_encode(array("message" => "Server error. Failed to update dispose."));
                }
            } else if ($method == 'DELETE') {
                $token = getToken($key, $algorithm);
                try {
                    $id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
                    if ($id) {
                        $dispose = new Dispose();
                        $dispose->getInstanceById($id);
                        $dispose->remove();
                        response(false, ['message' => 'Successfully deleted dispose with id ' . $id]);
                    } else {
                        response(true, ['message' => "Dispose id doesn't exist!"], 404);
                    }
                } catch (Exception $e) {
                    response(true, ['error' => true, 'message' => $e->getMessage()], 400);
                }
            } else if ($method !== 'OPTIONS') {
                response(true, ['message' => 'Invalid command!'], 400);
            }
            break;
        default:
            response(true, ['message' => 'There is no such command!'], 400);
    }
} catch (Exception $e) {
    response(true, ['message' => $e->getMessage()], 500);
}
