import {Component, OnInit} from '@angular/core';
import {AuthService} from '../root/auth/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html'
})
export class LoginComponent implements OnInit {

  constructor() {
  }

  ngOnInit() {
  }

  login() {
    AuthService.login();
  }
}
