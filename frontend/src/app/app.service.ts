import {Injectable} from '@angular/core';
import {Observable} from 'rxjs/Observable';
import {HttpClient} from '@angular/common/http';
import {Endpoints} from "../constants/endpoints";
import {BehaviorSubject} from "rxjs";

@Injectable()
export class AppService {
  private messageSource: BehaviorSubject<string> = new BehaviorSubject("You are not logged in.");
  currentMessage = this.messageSource.asObservable();

  constructor(private http: HttpClient) {}

  public updateMessage(newMessage: string) {
    this.messageSource.next(newMessage);
  }

  public getWelcomeMessage(): Observable<any> {
    return this.http.get(Endpoints.WELCOME_API);
  }
}
