$(document).ready(function () {
    // DOM ready
    attachHandlers();
    saveProfile();

    // Load profile if it exists
    loadProfile();

    /**
     * Attach javascript handlers to elements.
     */
    function attachHandlers() {
        $("#another-user").on("click", resetProfile);
    }

    /**
     * Load the profile if exists in local storage.
     */
    function loadProfile() {
        if (!supportsHTML5Storage()) {
            return false;
        }

        let profileImgSrc = localStorage.getItem("PROFILE_IMG_SRC");
        let profileName = localStorage.getItem("PROFILE_NAME");
        let profileReAuthEmail = localStorage.getItem("PROFILE_EMAIL");

        if (profileName !== null
                && profileReAuthEmail !== null
                && profileImgSrc !== null) {
            $("#profile-img").attr("src", profileImgSrc);
            $("#profile-name").html(profileName);
            $("#profile-username").html(profileReAuthEmail);
            $("#username").val(profileReAuthEmail).hide();
            $("#password").focus();
            $("#remember").hide();
            $("#another-user").show();
        }
    }

    /**
     * Reset the profile in local storage and clear/reset the form.
     */
    function resetProfile() {
        localStorage.removeItem("PROFILE_IMG_SRC");
        localStorage.removeItem("PROFILE_NAME");
        localStorage.removeItem("PROFILE_EMAIL");
        $("#profile-img").attr("src", "//ssl.gstatic.com/accounts/ui/avatar_2x.png");
        $("#profile-name").html("");
        $("#profile-username").html("");
        $("#username").val("").show().focus();
        $("#password").val("");
        $("#remember").show();
        $("#another-user").hide();
        return false;
    }

    /**
     * Save the profile in local storage.
     */
    function saveProfile() {
        if (!supportsHTML5Storage()) {
            return false;
        }

        let email = $("#data-username").val();
        let name = $("#data-name").val();
        let profileImage = $("#data-profile-img").val();
        if (email === undefined || name === undefined || profileImage === undefined) {
            return;
        }
        localStorage.setItem("PROFILE_EMAIL", email);
        localStorage.setItem("PROFILE_NAME", name);
        localStorage.setItem("PROFILE_IMG_SRC", profileImage);
    }

    /**
     * Check if the browser supports HTML5 local storage.
     *
     * @returns {boolean} true if local storage is supported, false otherwise
     */
    function supportsHTML5Storage() {
        try {
            return 'localStorage' in window && window['localStorage'] !== null;
        } catch (e) {
            return false;
        }
    }
});