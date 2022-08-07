package com.aurel.springSecurity.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Aurel Chivu"),
            new Student(2, "James Bond"),
            new Student(3, "John Doe")
    );

    @GetMapping
    public List<Student> getAllStudents() {
        System.out.println("getAllStudents");
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("registerNewStudent");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("deleteStudent");
        System.out.println("Student with the id " + studentId + " was deleted");
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId")  Integer studentId, @RequestBody Student student) {
        System.out.println("updateStudent");
        System.out.println("Student with the id " + studentId + " was updated");
    }
}
