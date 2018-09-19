import {Component, OnInit} from '@angular/core';
import {AppService} from "./app.service";

@Component({
  selector: 'app-home',
  templateUrl: './app.component.html'
})
export class AppComponent implements OnInit{
  message: string;

  constructor(private appService: AppService) {}

  ngOnInit() {
    this.appService.currentMessage.subscribe(message => this.message = message)
  }
}
