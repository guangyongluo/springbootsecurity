package com.vilin.springboot.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/product")
public class ProductController {

    @RequestMapping("/add")
    public String add(){
        return "product/add";
    }

    @RequestMapping("/delete")
    public String delete(){
        return "product/delete";
    }

    @RequestMapping("/update")
    public String update(){
        return "product/update";
    }

    @RequestMapping("/list")
    public String list(){
        return "product/list";
    }

}
