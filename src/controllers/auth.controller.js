import { ApiError } from "../utils/customResponse/ApiError.js";
import { ApiResponse } from "../utils/customResponse/ApiResponse.js";
import { User } from "../models/user.model.js";
import { Session } from "../models/session.model.js";
import { checkPasswordStrength } from "../utils/others/checkPasswordStrength.js";

// generate access and refresh token
const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);

        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;

        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        console.log(error);
        throw new ApiError(
            500,
            "Something went wrong while generating referesh and access token"
        );
    }
};

// register user controller
export const registerUser = async (req, res, next) => {
    try {
        const { fullName, email, dob, phone, address, password } = req.body;

        if (!fullName || !dob || !address || !email || !phone || !password) {
            return res
                .status(400)
                .json(new ApiError(400, "All fields are required"));
        }

        const isPasswordStrong = checkPasswordStrength(password);

        if (!isPasswordStrong) {
            return res
                .status(422)
                .json(
                    new ApiError(
                        402,
                        "Password must be strong: at least 6 characters, including one uppercase letter, one lowercase letter, one number, and one symbol."
                    )
                );
        }

        const existedUser = await User.findOne({
            $or: [{ email }, { phone }],
        });

        if (existedUser) {
            return res
                .status(409)
                .json(
                    new ApiError(409, "User with this email already exists.")
                );
        }

        const user = await User.create({
            fullName,
            email,
            phone,
            dob,
            address,
            password,
        });

        const createdUser = await User.findById(user._id).select("-password");

        return res
            .status(201)
            .json(
                new ApiResponse(201, createdUser, "User successfully created.")
            );
    } catch (error) {
        console.error(`Internal Server Error : ${error}`);
        return next(new ApiError(500, "Server error registering user."));
    }
};

// login user controller
export const loginUser = async (req, res, next) => {
    try {
        // get the email password
        const { email, password } = req.body;

        if (!email || !password) {
            return res
                .status(401)
                .json(new ApiError(401, "All fields are required"));
        }

        // check if user exists
        const user = await User.findOne({ email });

        if (!user) {
            return res
                .status(404)
                .json(new ApiError(404, "User with this email doesnot exist."));
        }

        const isPasswordCorrect = await user.isPasswordCorrect(password);

        // check if the password is correct
        if (!isPasswordCorrect) {
            return res.status(401).json(new ApiError(401, "Invalid Password."));
        }
        // create tokens
        const { accessToken, refreshToken } =
            await generateAccessAndRefreshToken(user._id);
        // create session token and save it to the db
        const session = await Session.create({
            token: accessToken,
            associate: user.email,
        });

        if (!session) {
            return res
                .status(500)
                .json(new ApiError(500, "Failed to create session token."));
        }

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken },
                    "Login Successful."
                )
            );
    } catch (error) {
        console.error(`Internal Server Error : ${error}`);
        return next(new ApiError(500, "Server error logging user in."));
    }
};

// google login controller
export const googleAuthCallback = async (
    accessToken,
    refreshToken,
    profile,
    done
) => {
    try {
        const { id, displayName, emails } = profile;
        const email = emails[0].value;
        const fullName = displayName;

        let user = await User.findOne({ email });

        if (!user) 
            user = await User.create({
                fullName,
                email,
                dob: null,
                password: null,
                address: null,
                status: "Active",
                googleId: id,
            });
        }

        // Ensure this user was created using Google (googleId is present)
        if (!user.googleId) {
            return done(null, false, {
                message: "This email is already registered but not via Google",
            });
        }

        return done(null, user);
    } catch (error) {
        console.error("Error in Google login callback:", error);
        return done(error, null);
    }
};

export const loginSuccess = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json(new ApiResponse("Not Authorized"));
        }

        const user = req.user;

        const dbUser = await User.findOne({ email: user.email });

        const { accessToken, refreshToken } =
            await generateAccessAndRefreshToken(dbUser._id);

        dbUser.refreshToken = refreshToken;

        const session = await Session.create({
            token: accessToken,
            associate: dbUser.email,
        });

        if (!session) {
            return res
                .status(500)
                .json(new ApiError(500, "Failed to create session token."));
        }

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken },
                    "Login Successful"
                )
            );
    } catch (error) {
        console.error("Internal Server Error:", error);
        return res
            .status(500)
            .json(new ApiError(500, "Server error during login success"));
    }
};
