package com.ambradev.oauth2app.providers;

import com.ambradev.oauth2app.model.UserBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.social.connect.ConnectionRepository;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.social.facebook.api.User;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;


@Service
public class FacebookProvider {

    private static final String FACEBOOK = "facebook";
    private static final String REDIRECT_LOGIN = "redirect:/login";

    @Autowired
    BaseProvider baseProvider;

    public String getFacebookUserData(Model model, UserBean userBean) {

        ConnectionRepository connectionRepository = baseProvider.getConnectionRepository();
        if (connectionRepository.findPrimaryConnection(Facebook.class) == null) {
            return REDIRECT_LOGIN;
        }
        //Populate the Bean
        populateUserDetailsFromFacebook(userBean);
        //Check if all Info has been collected
        if (!baseProvider.isAllInformationAvailable(userBean)) {
            model.addAttribute("userBean", userBean);
            return "incompleteInfo";
        }
        //Save the details in DB
        baseProvider.saveUserDetails(userBean);
        //Login the User
        baseProvider.autoLoginUser(userBean);
        model.addAttribute("loggedInUser", userBean);
        return "secure/user";
    }

    protected void populateUserDetailsFromFacebook(UserBean userForm) {
        Facebook facebook = baseProvider.getFacebook();

        String [] fields = { "id", "email", "first_name", "last_name", "picture" };
        User user = facebook.fetchObject("me", User.class, fields);
        userForm.setEmail(user.getEmail());
        userForm.setFirstName(user.getFirstName());
        userForm.setLastName(user.getLastName());
        //TODO: Fetch profile picture.
//        userForm.setImage(user.getCover().getSource());
        userForm.setProvider(FACEBOOK);
    }
}
