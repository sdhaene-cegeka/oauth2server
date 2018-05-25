package com.ambradev.oauth2app.controller;

import com.ambradev.oauth2app.autologin.Autologin;
import com.ambradev.oauth2app.model.UserBean;
import com.ambradev.oauth2app.providers.FacebookProvider;
import com.ambradev.oauth2app.providers.GoogleProvider;
import com.ambradev.oauth2app.providers.LinkedInProvider;
import com.ambradev.oauth2app.repository.UserRepository;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@Controller
public class LoginController {

    @Autowired
    FacebookProvider facebookProvider;

    @Autowired
    GoogleProvider googleProvider;

    @Autowired
    LinkedInProvider linkedInProvider;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private Autologin autologin;

    @RequestMapping(value = "/facebook", method = RequestMethod.GET)
    public String loginToFacebook(Model model) {
	return facebookProvider.getFacebookUserData(model, new UserBean());
    }

    @RequestMapping(value = "/google", method = RequestMethod.GET)
    public String loginToGoogle(Model model) {
	return googleProvider.getGoogleUserData(model, new UserBean());
    }

    @RequestMapping(value = "/linkedin", method = RequestMethod.GET)
    public String helloFacebook(Model model) {
	return linkedInProvider.getLinkedInUserData(model, new UserBean());
    }

    @RequestMapping(value = { "/", "/login" })
    public String login() {
	return "login";
    }

    @GetMapping("/registration")
    public String showRegistration(UserBean userBean) {
	return "registration";
    }

    @PostMapping("/registration")
    public String registerUser(HttpServletResponse httpServletResponse, Model model, @Valid UserBean userBean, BindingResult bindingResult) {
	if (bindingResult.hasErrors()) {
	    return "registration";
	}
	userBean.setProvider("REGISTRATION");
	// Save the details in DB
	if (StringUtils.isNotEmpty(userBean.getPassword())) {
	    userBean.setPassword(bCryptPasswordEncoder.encode(userBean.getPassword()));
	}
	userRepository.save(userBean);

	autologin.setSecurityContext(userBean);

	model.addAttribute("loggedInUser", userBean);
	return "secure/user";
    }

    /** If we can't find a user/email combination */
    @RequestMapping("/login-error")
    public String loginError(Model model) {
	model.addAttribute("loginError", true);
	return "login";
    }

}
